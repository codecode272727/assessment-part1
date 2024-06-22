provider "aws" {
  region = "ap-southeast-1"  # Replace with your preferred AWS region
}

# VPC
resource "aws_vpc" "main_vpc" {
  cidr_block           = "192.168.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "MainVPC"
  }
}

# Subnets
resource "aws_subnet" "public_subnet_a" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = "192.168.1.0/24"
  availability_zone       = "ap-southeast-1a"
  map_public_ip_on_launch = true

  tags = {
    Name = "PublicSubnetA"
  }
}

resource "aws_subnet" "public_subnet_b" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = "192.168.2.0/24"
  availability_zone       = "ap-southeast-1b"
  map_public_ip_on_launch = true

  tags = {
    Name = "PublicSubnetB"
  }
}

resource "aws_subnet" "private_subnet_a" {
  vpc_id            = aws_vpc.main_vpc.id
  cidr_block        = "192.168.3.0/24"
  availability_zone = "ap-southeast-1a"

  tags = {
    Name = "PrivateSubnetA"
  }
}

resource "aws_subnet" "private_subnet_b" {
  vpc_id            = aws_vpc.main_vpc.id
  cidr_block        = "192.168.4.0/24"
  availability_zone = "ap-southeast-1b"

  tags = {
    Name = "PrivateSubnetB"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main_vpc.id

  tags = {
    Name = "MainIGW"
  }
}

# Elastic IP for NAT Gateway in 1st AZ
resource "aws_eip" "nat_eip_a" {
  domain = "vpc"
}

# Elastic IP for NAT Gateway in 2nd AZ
resource "aws_eip" "nat_eip_b" {
  domain = "vpc"
}

# NAT Gateway in 1st AZ
resource "aws_nat_gateway" "nat_gw_a" {
  allocation_id = aws_eip.nat_eip_a.id
  subnet_id     = aws_subnet.public_subnet_a.id

  tags = {
    Name = "NATGatewayA"
  }
}

# NAT Gateway in 2nd AZ
resource "aws_nat_gateway" "nat_gw_b" {
  allocation_id = aws_eip.nat_eip_b.id
  subnet_id     = aws_subnet.public_subnet_b.id

  tags = {
    Name = "NATGatewayB"
  }
}

# Main Route Table
resource "aws_route_table" "main_rt" {
  vpc_id = aws_vpc.main_vpc.id

  route {
    cidr_block = "192.168.0.0/16"
    gateway_id = "local"
  }

  tags = {
    Name = "MainRouteTable"
  }
}

# Associate the VPC with the Main Route Table
resource "aws_main_route_table_association" "main_rt_assoc" {
  vpc_id         = aws_vpc.main_vpc.id
  route_table_id = aws_route_table.main_rt.id
}

# Public Route Table
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.main_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "PublicRouteTable"
  }
}

resource "aws_route_table_association" "public_rt_assoc_a" {
  subnet_id      = aws_subnet.public_subnet_a.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "public_rt_assoc_b" {
  subnet_id      = aws_subnet.public_subnet_b.id
  route_table_id = aws_route_table.public_rt.id
}

# Private Route Table
resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.main_vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_gw_a.id
  }

  tags = {
    Name = "PrivateRouteTableA"
  }
}

resource "aws_route_table_association" "private_rt_assoc_a" {
  subnet_id      = aws_subnet.private_subnet_a.id
  route_table_id = aws_route_table.private_rt.id
}

resource "aws_route_table" "private_rt_b" {
  vpc_id = aws_vpc.main_vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_gw_b.id
  }

  tags = {
    Name = "PrivateRouteTableB"
  }
}

resource "aws_route_table_association" "private_rt_assoc_b" {
  subnet_id      = aws_subnet.private_subnet_b.id
  route_table_id = aws_route_table.private_rt_b.id
}

# Security Group for RDS
resource "aws_security_group" "sg_rds" {
  name        = "sg_rds"
  description = "Allow access to RDS"
  vpc_id      = aws_vpc.main_vpc.id

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["192.168.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "sg-rds"
  }
}

resource "aws_security_group" "sg-ec2" {
  vpc_id = aws_vpc.main_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "sg-ec2"
  }
}

resource "aws_security_group" "sg_ssm" {
  vpc_id = aws_vpc.main_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "sg-ssm"
  }
}

# EC2 instance for SSM Host in public subnet of 1st AZ
resource "aws_instance" "ssm_host" {
  ami           = "ami-080367f396ea04ea7" 
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.public_subnet_a.id
  key_name      = "my-key-pair"    
  vpc_security_group_ids = [aws_security_group.sg_ssm.id]    

  iam_instance_profile = aws_iam_instance_profile.ssm_instance_profile.name   

  tags = {
    Name = "SSMHost"
  }

  user_data = <<-EOF
              #!/bin/bash
              yum install -y amazon-ssm-agent
              systemctl start amazon-ssm-agent
              systemctl enable amazon-ssm-agent
              EOF
}

# RDS instances
resource "aws_db_instance" "mariadb_master" {
  identifier           = "masterdb"
  instance_class       = "db.t3.micro"
  engine               = "mariadb"
  engine_version       = "10.4"
  allocated_storage    = 20
  username             = "admin"
  password             = "password"  # Replace with secure method like AWS Secrets Manager
  skip_final_snapshot  = true

  db_subnet_group_name = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.sg_rds.id]
  backup_retention_period = 5
  apply_immediately = true
  tags = {
    Name = "mariadb-master"
  }
}

resource "aws_db_instance" "mariadb_replica" {
  identifier           = "replicadb"
  instance_class       = "db.t3.micro"
  engine               = "mariadb"
  engine_version       = "10.4"
  replicate_source_db  = aws_db_instance.mariadb_master.identifier
  skip_final_snapshot  = true 
  apply_immediately = true
  vpc_security_group_ids = [aws_security_group.sg_rds.id]

  depends_on = [aws_db_instance.mariadb_master]

  tags = {
    Name = "mariadb-replica"
  }
}

resource "aws_db_subnet_group" "main" {
  name       = "main-subnet-group"
  subnet_ids = [aws_subnet.private_subnet_a.id, aws_subnet.private_subnet_b.id]

  tags = {
    Name = "main-db-subnet-group"
  }
}

# VPC Endpoint for SSM
resource "aws_vpc_endpoint" "ssm" {
  vpc_id       = aws_vpc.main_vpc.id
  service_name      = "com.amazonaws.ap-southeast-1.ssm"
  vpc_endpoint_type = "Interface"
  subnet_ids        = [aws_subnet.private_subnet_a.id, aws_subnet.private_subnet_b.id]
  security_group_ids = [aws_security_group.ssm_sg.id]

  tags = {
    Name = "ssm-endpoint"
  }
}

# Security Group for SSM VPC Endpoint
resource "aws_security_group" "ssm_sg" {
  name        = "ssm-endpoint-sg"
  description = "Allow access to SSM endpoint"
  vpc_id      = aws_vpc.main_vpc.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Adjust CIDR blocks as necessary for your security requirements
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1" # Allows all outbound traffic
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ssm-endpoint-sg"
  }
}

# Create SSM Role and Policy
resource "aws_iam_role" "ssm_role" {
  name = "ssm_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ssm.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm_role_policy_attachment" {
  role       = aws_iam_role.ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ssm_instance_profile" {
  name = "ssm_instance_profile"
  role = aws_iam_role.ssm_role.name
}

# EC2 instance in private subnet of 2nd AZ
resource "aws_instance" "server_instance" {
  ami           = "ami-080367f396ea04ea7" 
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.private_subnet_b.id
  key_name      = "my-key-pair"           
  vpc_security_group_ids = [aws_security_group.sg-ec2.id]

  iam_instance_profile = aws_iam_instance_profile.ssm_instance_profile.name

  tags = {
    Name = "PrivateServer"
  }
}

# ASG for EC2 instances in private subnet of 2nd AZ
resource "aws_autoscaling_group" "asg" {
  desired_capacity     = 1
  max_size             = 2
  min_size             = 1
  vpc_zone_identifier  = [aws_subnet.private_subnet_b.id]
  launch_configuration = aws_launch_configuration.asg_lc.id

  tag {
    key                 = "Name"
    value               = "ASGInstance"
    propagate_at_launch = true
  }
}

# Launch Configuration for ASG
resource "aws_launch_configuration" "asg_lc" {
  name          = "asg-launch-configuration"
  image_id      = "ami-080367f396ea04ea7" 
  instance_type = "t2.micro"
  key_name      = "my-key-pair"          

  lifecycle {
    create_before_destroy = true
  }
}

# S3 Bucket for static files
resource "aws_s3_bucket" "static_site" {
  bucket = "s3-bucket-03783698mm20062024"
  force_destroy = true

  tags = {
    Name = "static-site-bucket"
  }
}


# S3 Bucket Policy
resource "aws_s3_bucket_policy" "static_site_policy" {
  bucket = aws_s3_bucket.static_site.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid: "PublicReadGetObject",
        Effect: "Allow",
        Principal: "*",
        Action: "s3:GetObject",
        Resource: "${aws_s3_bucket.static_site.arn}/*"
      }
    ]
  })
}

# Output the CloudFront distribution ID
output "cloudfront_distribution_id" {
  value = aws_cloudfront_distribution.s3_distribution.id
}

resource "aws_s3_bucket_public_access_block" "block_public_access" {
  bucket = aws_s3_bucket.static_site.id

  block_public_acls       = true
  block_public_policy     = false 
  ignore_public_acls      = true
  restrict_public_buckets = false  
}


# CloudFront Distribution
resource "aws_cloudfront_distribution" "s3_distribution" {
  origin {
    domain_name = aws_s3_bucket.static_site.bucket_regional_domain_name
    origin_id   = "S3-static-site"
    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.oai.cloudfront_access_identity_path
    }
  }

  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "S3-static-site"
    viewer_protocol_policy = "redirect-to-https"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    min_ttl     = 0
    default_ttl = 3600
    max_ttl     = 86400
  }

  price_class = "PriceClass_100"
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  tags = {
    Name = "static-site-distribution"
  }
}

resource "aws_cloudfront_origin_access_identity" "oai" {
  comment = "S3 bucket access for CloudFront"
}

# Public NLB
resource "aws_lb" "public_nlb" {
  name               = "public-nlb"
  internal           = false
  load_balancer_type = "network"
  subnets            = [aws_subnet.public_subnet_a.id, aws_subnet.public_subnet_b.id]

  tags = {
    Name = "PublicNLB"
  }
}

# Target Group for NLB
resource "aws_lb_target_group" "tg" {
  name     = "tg"
  port     = 80
  protocol = "TCP"
  vpc_id   = aws_vpc.main_vpc.id

  health_check {
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    interval            = 10
    matcher             = "200"
  }

  tags = {
    Name = "NLBTargetGroup"
  }
}

# Listener for NLB
resource "aws_lb_listener" "listener" {
  load_balancer_arn = aws_lb.public_nlb.arn
  port              = 80
  protocol          = "TCP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg.arn
  }

  tags = {
    Name = "NLBListener"
  }
}

# Register EC2 instances with Target Group
resource "aws_lb_target_group_attachment" "asg" {
  target_group_arn = aws_lb_target_group.tg.arn
  target_id        = aws_instance.server_instance.id
  port             = 80
}
