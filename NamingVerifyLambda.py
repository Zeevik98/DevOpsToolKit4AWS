import boto3
import json
import os
import re
from typing import Dict, List, Optional
from datetime import datetime

class ResourceProcessor:
    def __init__(self):
        self.env_patterns = self._get_env_patterns()
        self.required_tags = self._get_required_tags()
        
    def _get_env_patterns(self) -> Dict:
        """Get naming patterns from environment variables"""
        return {
            'EC2': os.environ.get('EC2_PATTERN', '{env}-{service}-{purpose}'),
            'S3': os.environ.get('S3_PATTERN', '{env}-{purpose}-{team}'),
            'RDS': os.environ.get('RDS_PATTERN', '{env}-{service}-{purpose}'),
            'LAMBDA': os.environ.get('LAMBDA_PATTERN', '{env}-{service}-{function}'),
            'DEFAULT': os.environ.get('DEFAULT_PATTERN', '{env}-{service}')
        }
    
    def _get_required_tags(self) -> Dict:
        """Get required tags from environment variables"""
        default_tags = {
            'Environment': os.environ.get('ENV', 'dev'),
            'Owner': os.environ.get('DEFAULT_OWNER', 'devops'),
            'CostCenter': os.environ.get('COST_CENTER', 'engineering')
        }
        
        # Add any additional tags defined in environment
        extra_tags = os.environ.get('ADDITIONAL_TAGS', '{}')
        try:
            default_tags.update(json.loads(extra_tags))
        except json.JSONDecodeError:
            print(f"Warning: Could not parse ADDITIONAL_TAGS: {extra_tags}")
            
        return default_tags

    def validate_name(self, resource_type: str, name: str) -> bool:
        """Validate resource name against pattern"""
        pattern = self.env_patterns.get(resource_type, self.env_patterns['DEFAULT'])
        try:
            # Convert pattern to regex
            regex_pattern = pattern.replace('{', '(?P<').replace('}', '>[a-zA-Z0-9-_]+)')
            return bool(re.match(regex_pattern, name))
        except re.error:
            print(f"Warning: Invalid pattern for {resource_type}: {pattern}")
            return True

    def generate_tags(self, resource_type: str, event_details: Dict) -> List[Dict]:
        """Generate tags based on resource type and event"""
        tags = []
        
        # Add required tags
        for key, value in self.required_tags.items():
            tags.append({
                'Key': key,
                'Value': value
            })
            
        # Add creation time tag
        tags.append({
            'Key': 'CreationTimestamp',
            'Value': datetime.utcnow().isoformat()
        })
        
        # Add resource-specific tags
        if resource_type in ['EC2', 'RDS']:
            tags.append({
                'Key': 'Backup',
                'Value': os.environ.get('DEFAULT_BACKUP', 'true')
            })
            
        return tags

    def process_resource(self, event: Dict) -> Dict:
        """Process resource creation event"""
        resource_type = event.get('detail', {}).get('service')
        resource_id = event.get('detail', {}).get('resource-id')
        
        if not resource_type or not resource_id:
            raise ValueError("Missing resource type or ID in event")
            
        # Generate tags
        tags = self.generate_tags(resource_type, event.get('detail', {}))
        
        # Apply tags based on resource type
        try:
            if resource_type == 'EC2':
                ec2 = boto3.client('ec2')
                ec2.create_tags(Resources=[resource_id], Tags=tags)
            elif resource_type == 'S3':
                s3 = boto3.client('s3')
                s3.put_bucket_tagging(
                    Bucket=resource_id,
                    Tagging={'TagSet': tags}
                )
            # Add more resource types as needed
            
            return {
                'resourceId': resource_id,
                'resourceType': resource_type,
                'appliedTags': tags,
                'status': 'SUCCESS'
            }
            
        except Exception as e:
            print(f"Error tagging resource {resource_id}: {str(e)}")
            return {
                'resourceId': resource_id,
                'resourceType': resource_type,
                'error': str(e),
                'status': 'FAILED'
            }

def lambda_handler(event: Dict, context) -> Dict:
    """Main Lambda handler"""
    try:
        processor = ResourceProcessor()
        result = processor.process_resource(event)
        
        # Send notification if configured
        if os.environ.get('SNS_TOPIC_ARN'):
            sns = boto3.client('sns')
            sns.publish(
                TopicArn=os.environ['SNS_TOPIC_ARN'],
                Subject=f"Resource Tagging {result['status']}",
                Message=json.dumps(result, indent=2)
            )
            
        return {
            'statusCode': 200 if result['status'] == 'SUCCESS' else 500,
            'body': result
        }
        
    except Exception as e:
        error_response = {
            'statusCode': 500,
            'body': {
                'error': str(e),
                'status': 'FAILED'
            }
        }
        return error_response
