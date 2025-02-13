import boto3
import json
from datetime import datetime, timedelta
import os
from typing import Dict, List

def get_all_regions() -> List[str]:
    """Get list of all AWS regions"""
    ec2_client = boto3.client('ec2')
    regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
    return regions

def check_certificate(cert_details: Dict, region: str) -> Dict:
    """Analyze certificate details and return status"""
    cert_arn = cert_details['CertificateArn']
    domain_name = cert_details['DomainName']
    expiry_date = cert_details.get('NotAfter')
    
    if not expiry_date:
        return {
            'status': 'WARNING',
            'message': f'No expiry date found for certificate {domain_name} in {region}',
            'arn': cert_arn
        }
    
    # Convert to datetime for comparison
    expiry_datetime = expiry_date.replace(tzinfo=None)
    current_time = datetime.utcnow()
    
    # Calculate days until expiration
    days_to_expiry = (expiry_datetime - current_time).days
    
    # Check validation status
    validation_status = cert_details.get('Status', 'UNKNOWN')
    
    if days_to_expiry <= 7:
        status = 'CRITICAL'
        message = f'Certificate for {domain_name} expires in {days_to_expiry} days!'
    elif days_to_expiry <= 30:
        status = 'WARNING'
        message = f'Certificate for {domain_name} expires in {days_to_expiry} days'
    elif validation_status != 'ISSUED':
        status = 'WARNING'
        message = f'Certificate for {domain_name} has validation status: {validation_status}'
    else:
        status = 'OK'
        message = f'Certificate for {domain_name} is valid for {days_to_expiry} days'
    
    return {
        'status': status,
        'message': message,
        'domain': domain_name,
        'arn': cert_arn,
        'region': region,
        'expiry_date': expiry_datetime.isoformat(),
        'days_to_expiry': days_to_expiry,
        'validation_status': validation_status
    }

def scan_certificates() -> List[Dict]:
    """Scan all regions for ACM certificates"""
    regions = get_all_regions()
    all_certificates = []
    
    for region in regions:
        acm_client = boto3.client('acm', region_name=region)
        
        try:
            paginator = acm_client.get_paginator('list_certificates')
            for page in paginator.paginate():
                for cert in page['CertificateSummaryList']:
                    try:
                        cert_details = acm_client.describe_certificate(
                            CertificateArn=cert['CertificateArn']
                        )['Certificate']
                        
                        cert_status = check_certificate(cert_details, region)
                        all_certificates.append(cert_status)
                        
                    except Exception as e:
                        print(f"Error processing certificate {cert['CertificateArn']}: {str(e)}")
                        
        except Exception as e:
            print(f"Error scanning region {region}: {str(e)}")
    
    return all_certificates

def send_notification(certificates: List[Dict]) -> None:
    """Send SNS notifications for certificates requiring attention"""
    sns_client = boto3.client('sns')
    topic_arn = os.environ['SNS_TOPIC_ARN']
    
    # Group certificates by status
    critical = [cert for cert in certificates if cert['status'] == 'CRITICAL']
    warnings = [cert for cert in certificates if cert['status'] == 'WARNING']
    
    if critical or warnings:
        message = {
            'timestamp': datetime.utcnow().isoformat(),
            'critical_certificates': critical,
            'warning_certificates': warnings,
            'total_certificates': len(certificates),
            'certificates_needing_attention': len(critical) + len(warnings)
        }
        
        sns_client.publish(
            TopicArn=topic_arn,
            Subject='ACM Certificate Status Alert',
            Message=json.dumps(message, indent=2)
        )

def lambda_handler(event: Dict, context) -> Dict:
    """Main Lambda handler"""
    try:
        # Scan all certificates
        certificates = scan_certificates()
        
        # Send notifications if needed
        send_notification(certificates)
        
        # Prepare summary
        summary = {
            'total_certificates': len(certificates),
            'critical': len([c for c in certificates if c['status'] == 'CRITICAL']),
            'warnings': len([c for c in certificates if c['status'] == 'WARNING']),
            'ok': len([c for c in certificates if c['status'] == 'OK']),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return {
            'statusCode': 200,
            'body': {
                'summary': summary,
                'certificates': certificates
            }
        }
        
    except Exception as e:
        print(f"Error in lambda execution: {str(e)}")
        return {
            'statusCode': 500,
            'body': f"Error executing certificate scan: {str(e)}"
        }
