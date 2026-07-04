output "vpc_id" {
  description = "ID de la VPC del SOC"
  value       = aws_vpc.soc.id
}

output "vpc_cidr" {
  description = "CIDR de la VPC"
  value       = aws_vpc.soc.cidr_block
}

output "public_subnet_id" {
  description = "ID de la subred pública"
  value       = aws_subnet.public.id
}

output "private_subnet_id" {
  description = "ID de la subred privada"
  value       = aws_subnet.private.id
}

output "lambda_sg_id" {
  description = "ID del Security Group para Lambda (SOAR)"
  value       = aws_security_group.lambda.id
}

output "isolation_sg_id" {
  description = "ID del Security Group de aislamiento (cuarentena de instancias)"
  value       = aws_security_group.isolation.id
}
