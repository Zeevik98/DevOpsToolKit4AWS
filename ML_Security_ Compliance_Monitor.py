import boto3
import json
import os
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any
from concurrent.futures import ThreadPoolExecutor
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MLSecurityMonitor:
    def __init__(self):
        # Validate environment variables
        required_vars = ['REPORT_BUCKET', 'ALERT_TOPIC_ARN', 'COMPLIANCE_LEVEL', 
                        'MIN_ENCRYPTION_LEVEL', 'ALLOWED_REGIONS']
        missing_vars = [var for var in required_vars if not os.environ.get(var)]
        if missing_vars:
            raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")
            
        # Initialize AWS clients
        self.sagemaker = boto3.client('sagemaker')
        self.s3 = boto3.client('s3')
        self.ecr = boto3.client('ecr')
        self.cloudtrail = boto3.client('cloudtrail')
        self.config = boto3.client('config')
        self.security_hub = boto3.client('securityhub')
        
        # Initialize correlation ID for tracing
        self.correlation_id = datetime.utcnow().strftime('%Y%m%d-%H%M%S')

    def _log_operation(func):
        """Decorator for operation logging"""
        def wrapper(self, *args, **kwargs):
            start_time = datetime.utcnow()
            logger.info(f"Starting {func.__name__} - Correlation ID: {self.correlation_id}")
            try:
                result = func(self, *args, **kwargs)
                logger.info(f"Completed {func.__name__} - Duration: {datetime.utcnow() - start_time}")
                return result
            except Exception as e:
                logger.error(f"Error in {func.__name__}: {str(e)}")
                raise
        return wrapper

    @_log_operation
    def check_sagemaker_compliance(self) -> Dict:
        """Check SageMaker resources compliance"""
        findings = []
        
        try:
            # Get all training jobs with pagination
            training_jobs = []
            paginator = self.sagemaker.get_paginator('list_training_jobs')
            for page in paginator.paginate():
                training_jobs.extend(page['TrainingJobSummaries'])
                
            # Process training jobs in parallel
            with ThreadPoolExecutor(max_workers=10) as executor:
                job_findings = list(executor.map(
                    self._validate_training_job,
                    [job['TrainingJobName'] for job in training_jobs]
                ))
                findings.extend([f for sublist in job_findings for f in sublist])
                
            # Check endpoints with pagination
            endpoints = []
            paginator = self.sagemaker.get_paginator('list_endpoints')
            for page in paginator.paginate():
                endpoints.extend(page['Endpoints'])
                
            # Process endpoints in parallel
            with ThreadPoolExecutor(max_workers=10) as executor:
                endpoint_findings = list(executor.map(
                    self._validate_endpoint,
                    [endpoint['EndpointName'] for endpoint in endpoints]
                ))
                findings.extend([f for sublist in endpoint_findings for f in sublist])
                
        except ClientError as e:
            logger.error(f"Error accessing SageMaker resources: {str(e)}")
            return self._format_findings('SageMaker', [])
            
        return self._format_findings('SageMaker', findings)

    @_log_operation
    def check_data_storage_compliance(self) -> Dict:
        """Check S3 and data storage compliance"""
        findings = []
        
        try:
            buckets = self.s3.list_buckets()['Buckets']
            
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                for bucket in buckets:
                    futures.append(
                        executor.submit(self._check_bucket_compliance, bucket['Name'])
                    )
                
                for future in futures:
                    bucket_findings = future.result()
                    if bucket_findings:
                        findings.extend(bucket_findings)
                        
        except ClientError as e:
            logger.error(f"Error checking data storage compliance: {str(e)}")
            return self._format_findings('DataStorage', [])
            
        return self._format_findings('DataStorage', findings)

    def _check_bucket_compliance(self, bucket_name: str) -> List[Dict]:
        """Check individual bucket compliance"""
        findings = []
        try:
            encryption = self.s3.get_bucket_encryption(Bucket=bucket_name)
            if 'ServerSideEncryptionConfiguration' not in encryption:
                findings.append({
                    'Severity': 'HIGH',
                    'Resource': bucket_name,
                    'Control': 'SC-13',
                    'Finding': 'Bucket not encrypted',
                    'Recommendation': 'Enable default encryption with KMS'
                })
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                findings.append({
                    'Severity': 'CRITICAL',
                    'Resource': bucket_name,
                    'Control': 'SC-13',
                    'Finding': 'No encryption configuration',
                    'Recommendation': 'Configure bucket encryption immediately'
                })
            else:
                logger.error(f"Error checking bucket {bucket_name}: {str(e)}")
                
        return findings

    @_log_operation
    def check_container_security(self) -> Dict:
        """Check ECR container security"""
        findings = []
        
        try:
            repositories = []
            paginator = self.ecr.get_paginator('describe_repositories')
            for page in paginator.paginate():
                repositories.extend(page['repositories'])
                
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                for repo in repositories:
                    futures.append(
                        executor.submit(self._check_repository_security, repo)
                    )
                    
                for future in futures:
                    repo_findings = future.result()
                    if repo_findings:
                        findings.extend(repo_findings)
                        
        except ClientError as e:
            logger.error(f"Error checking container security: {str(e)}")
            return self._format_findings('ContainerSecurity', [])
            
        return self._format_findings('ContainerSecurity', findings)

    def _check_repository_security(self, repo: Dict) -> List[Dict]:
        """Check individual repository security"""
        findings = []
        try:
            scan_findings = self.ecr.describe_image_scan_findings(
                repositoryName=repo['repositoryName'],
                imageId={'imageTag': 'latest'}
            )
            findings.extend(self._analyze_scan_findings(scan_findings))
        except ClientError as e:
            logger.error(f"Error checking repository {repo['repositoryName']}: {str(e)}")
            
        return findings

    @_log_operation
    def generate_compliance_report(self) -> Dict:
        """Generate comprehensive compliance report"""
        report = {
            'timestamp': datetime.utcnow().isoformat(),
            'correlation_id': self.correlation_id,
            'summary': {
                'total_checks': 0,
                'violations': 0,
                'critical_findings': 0
            },
            'findings': []
        }
        
        # Run compliance checks in parallel
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(self.check_sagemaker_compliance),
                executor.submit(self.check_data_storage_compliance),
                executor.submit(self.check_container_security)
            ]
            
            for future in futures:
                try:
                    check_result = future.result()
                    report['findings'].extend(check_result['findings'])
                    report['summary']['total_checks'] += check_result['total_checks']
                    report['summary']['violations'] += check_result['violations']
                    report['summary']['critical_findings'] += check_result['critical_findings']
                except Exception as e:
                    logger.error(f"Error in compliance check: {str(e)}")
            
        return report

def lambda_handler(event: Dict[str, Any], context) -> Dict:
    """Main Lambda handler"""
    try:
        monitor = MLSecurityMonitor()
        report = monitor.generate_compliance_report()
        
        # Store report in S3
        s3_client = boto3.client('s3')
        report_bucket = os.environ['REPORT_BUCKET']
        report_key = f"compliance-reports/{datetime.utcnow().strftime('%Y-%m-%d')}/ml-security-report.json"
        
        try:
            s3_client.put_object(
                Bucket=report_bucket,
                Key=report_key,
                Body=json.dumps(report, indent=2),
                ContentType='application/json'
            )
        except ClientError as e:
            logger.error(f"Error storing report in S3: {str(e)}")
            
        # Send notifications if critical findings
        if report['summary']['critical_findings'] > 0:
            sns_client = boto3.client('sns')
            try:
                sns_client.publish(
                    TopicArn=os.environ['ALERT_TOPIC_ARN'],
                    Subject='Critical ML Security Findings Detected',
                    Message=json.dumps(report, indent=2)
                )
            except ClientError as e:
                logger.error(f"Error sending SNS notification: {str(e)}")
            
        return {
            'statusCode': 200,
            'body': report
        }
        
    except Exception as e:
        logger.error(f"Error in lambda execution: {str(e)}")
        return {
            'statusCode': 500,
            'body': str(e)
        }
