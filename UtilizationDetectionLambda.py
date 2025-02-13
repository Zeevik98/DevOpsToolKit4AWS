import boto3
import json
from datetime import datetime, timedelta
import os
from typing import Dict, List, Any

def get_cost_data(client, start_date: datetime, end_date: datetime) -> Dict:
    """Get AWS cost data for the specified time period"""
    try:
        response = client.get_cost_and_usage(
            TimePeriod={
                'Start': start_date.strftime('%Y-%m-%d'),
                'End': end_date.strftime('%Y-%m-%d')
            },
            Granularity='DAILY',
            Metrics=['UnblendedCost', 'UsageQuantity'],
            GroupBy=[
                {'Type': 'DIMENSION', 'Key': 'SERVICE'},
                {'Type': 'DIMENSION', 'Key': 'USAGE_TYPE'}
            ]
        )
        return response['ResultsByTime']
    except Exception as e:
        print(f"Error getting cost data: {str(e)}")
        return {}

def get_ec2_utilization() -> List[Dict]:
    """Get EC2 instance utilization metrics"""
    ec2_client = boto3.client('ec2')
    cloudwatch = boto3.client('cloudwatch')
    
    instances = ec2_client.describe_instances()
    instance_metrics = []
    
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            
            # Get CPU utilization
            cpu_response = cloudwatch.get_metric_statistics(
                Namespace='AWS/EC2',
                MetricName='CPUUtilization',
                Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                StartTime=datetime.utcnow() - timedelta(days=7),
                EndTime=datetime.utcnow(),
                Period=3600,
                Statistics=['Average']
            )
            
            avg_cpu = sum(point['Average'] for point in cpu_response['Datapoints']) / len(cpu_response['Datapoints']) if cpu_response['Datapoints'] else 0
            
            instance_metrics.append({
                'InstanceId': instance_id,
                'InstanceType': instance['InstanceType'],
                'AverageCPU': avg_cpu,
                'State': instance['State']['Name']
            })
    
    return instance_metrics

def generate_report(cost_data: Dict, utilization_data: List[Dict]) -> Dict:
    """Generate a comprehensive report combining cost and utilization data"""
    total_cost = 0
    service_costs = {}
    
    # Process cost data
    for day in cost_data:
        for group in day['Groups']:
            service = group['Keys'][0]
            cost = float(group['Metrics']['UnblendedCost']['Amount'])
            
            if service not in service_costs:
                service_costs[service] = 0
            service_costs[service] += cost
            total_cost += cost
    
    # Identify potential waste
    waste_candidates = []
    for instance in utilization_data:
        if instance['AverageCPU'] < 20 and instance['State'] == 'running':
            waste_candidates.append({
                'InstanceId': instance['InstanceId'],
                'InstanceType': instance['InstanceType'],
                'CPUUtilization': instance['AverageCPU'],
                'Recommendation': 'Consider downsizing or terminating'
            })
    
    return {
        'ReportTimestamp': datetime.utcnow().isoformat(),
        'TotalCost': round(total_cost, 2),
        'ServiceBreakdown': service_costs,
        'PotentialWaste': waste_candidates,
        'AverageDailyCost': round(total_cost / 7, 2) if cost_data else 0
    }

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict:
    """Main Lambda handler"""
    try:
        # Initialize clients
        cost_explorer = boto3.client('ce')
        sns = boto3.client('sns')
        s3 = boto3.client('s3')
        
        # Get environment variables
        sns_topic = os.environ['SNS_TOPIC_ARN']
        bucket_name = os.environ['S3_BUCKET_NAME']
        
        # Set time period for analysis
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=7)
        
        # Gather data
        cost_data = get_cost_data(cost_explorer, start_date, end_date)
        utilization_data = get_ec2_utilization()
        
        # Generate report
        report = generate_report(cost_data, utilization_data)
        
        # Save report to S3
        report_key = f"resource_reports/{datetime.utcnow().strftime('%Y-%m-%d')}_resource_report.json"
        s3.put_object(
            Bucket=bucket_name,
            Key=report_key,
            Body=json.dumps(report, indent=2)
        )
        
        # Send SNS notification
        sns_message = {
            'Report Summary': {
                'Total Weekly Cost': f"${report['TotalCost']}",
                'Average Daily Cost': f"${report['AverageDailyCost']}",
                'Waste Candidates Count': len(report['PotentialWaste']),
                'Report Location': f"s3://{bucket_name}/{report_key}"
            }
        }
        
        sns.publish(
            TopicArn=sns_topic,
            Subject='AWS Resource Utilization Report',
            Message=json.dumps(sns_message, indent=2)
        )
        
        return {
            'statusCode': 200,
            'body': 'Report generated and sent successfully'
        }
        
    except Exception as e:
        print(f"Error in lambda execution: {str(e)}")
        return {
            'statusCode': 500,
            'body': f"Error generating report: {str(e)}"
        }
