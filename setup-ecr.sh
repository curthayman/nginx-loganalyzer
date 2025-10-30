#!/bin/bash

# ECR Repository Setup Script for nginx-loganalyzer
# This script creates the ECR repository and sets up proper permissions

set -e  # Exit on any error

# Configuration
REPOSITORY_NAME="nginx-loganalyzer"
AWS_REGION="${AWS_REGION:-us-east-1}"
AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if AWS CLI is installed
check_aws_cli() {
    if ! command -v aws &> /dev/null; then
        print_error "AWS CLI is not installed. Please install it first:"
        echo "  https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
        exit 1
    fi
    print_success "AWS CLI found"
}

# Function to check AWS authentication
check_aws_auth() {
    print_status "Checking AWS authentication..."
    
    if ! aws sts get-caller-identity &> /dev/null; then
        print_error "AWS authentication failed. Please configure AWS credentials:"
        echo "  aws configure"
        echo "  or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables"
        exit 1
    fi
    
    # Get account ID if not provided
    if [ -z "$AWS_ACCOUNT_ID" ]; then
        AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
        print_status "Using AWS Account ID: $AWS_ACCOUNT_ID"
    fi
    
    print_success "AWS authentication verified"
}

# Function to create ECR repository
create_ecr_repository() {
    print_status "Creating ECR repository: $REPOSITORY_NAME"
    
    # Check if repository already exists
    if aws ecr describe-repositories --repository-names "$REPOSITORY_NAME" --region "$AWS_REGION" &> /dev/null; then
        print_warning "ECR repository '$REPOSITORY_NAME' already exists"
        REPO_URI=$(aws ecr describe-repositories --repository-names "$REPOSITORY_NAME" --region "$AWS_REGION" --query 'repositories[0].repositoryUri' --output text)
    else
        # Create the repository
        REPO_URI=$(aws ecr create-repository \
            --repository-name "$REPOSITORY_NAME" \
            --region "$AWS_REGION" \
            --image-scanning-configuration scanOnPush=true \
            --encryption-configuration encryptionType=AES256 \
            --query 'repository.repositoryUri' \
            --output text)
        
        print_success "ECR repository created successfully"
    fi
    
    print_success "Repository URI: $REPO_URI"
}

# Function to set repository lifecycle policy
set_lifecycle_policy() {
    print_status "Setting lifecycle policy to keep last 10 images..."
    
    cat > /tmp/lifecycle-policy.json << EOF
{
    "rules": [
        {
            "rulePriority": 1,
            "description": "Keep last 10 images",
            "selection": {
                "tagStatus": "any",
                "countType": "imageCountMoreThan",
                "countNumber": 10
            },
            "action": {
                "type": "expire"
            }
        }
    ]
}
EOF

    if aws ecr put-lifecycle-policy \
        --repository-name "$REPOSITORY_NAME" \
        --region "$AWS_REGION" \
        --lifecycle-policy-text file:///tmp/lifecycle-policy.json &> /dev/null; then
        print_success "Lifecycle policy applied"
    else
        print_warning "Failed to apply lifecycle policy (may not have permissions)"
    fi
    
    rm -f /tmp/lifecycle-policy.json
}

# Function to generate IAM policy
generate_iam_policy() {
    print_status "Generating IAM policy for repository-specific access..."
    
    cat > ecr-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ECRAuthToken",
            "Effect": "Allow",
            "Action": [
                "ecr:GetAuthorizationToken"
            ],
            "Resource": "*"
        },
        {
            "Sid": "ECRRepositoryAccess",
            "Effect": "Allow",
            "Action": [
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage",
                "ecr:PutImage",
                "ecr:InitiateLayerUpload",
                "ecr:UploadLayerPart",
                "ecr:CompleteLayerUpload",
                "ecr:DescribeRepositories",
                "ecr:DescribeImageScanFindings"
            ],
            "Resource": [
                "arn:aws:ecr:${AWS_REGION}:${AWS_ACCOUNT_ID}:repository/${REPOSITORY_NAME}"
            ]
        }
    ]
}
EOF

    print_success "IAM policy saved to: ecr-policy.json"
}

# Function to display next steps
display_next_steps() {
    echo
    echo "=========================================="
    echo "ECR Repository Setup Complete!"
    echo "=========================================="
    echo
    echo "Repository Details:"
    echo "  Name: $REPOSITORY_NAME"
    echo "  Region: $AWS_REGION"
    echo "  URI: $REPO_URI"
    echo "  Account ID: $AWS_ACCOUNT_ID"
    echo
    echo "Next Steps:"
    echo
    echo "1. Create/Update IAM Role or User with the policy in 'ecr-policy.json'"
    echo "   For GitHub Actions OIDC, attach this policy to your GitHub Actions role."
    echo
    echo "2. Add GitHub Secrets (if using GitHub Actions):"
    echo "   - AWS_ACCOUNT_ID: $AWS_ACCOUNT_ID"
    echo "   - AWS_REGION: $AWS_REGION"
    echo
    echo "3. Test Docker push locally:"
    echo "   aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"
    echo "   docker tag nginx-loganalyzer:latest $REPO_URI:latest"
    echo "   docker push $REPO_URI:latest"
    echo
    echo "4. Update your docker-compose.yml or GitHub Actions to use:"
    echo "   image: $REPO_URI:latest"
    echo
}

# Main execution
main() {
    echo "=========================================="
    echo "nginx-loganalyzer ECR Setup"
    echo "=========================================="
    echo
    
    # Validate input
    if [ -z "$AWS_REGION" ]; then
        print_error "AWS_REGION is required"
        echo "Usage: AWS_REGION=us-east-1 $0"
        exit 1
    fi
    
    # Run setup steps
    check_aws_cli
    check_aws_auth
    create_ecr_repository
    set_lifecycle_policy
    generate_iam_policy
    display_next_steps
}

# Run main function
main "$@"