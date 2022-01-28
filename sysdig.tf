provider "aws" {
  region = "us-west-2"
}

module "secure-for-cloud_example_single-account" {
  source = "sysdiglabs/secure-for-cloud/aws//examples/single-account"

  sysdig_secure_endpoint = "https://us2.app.sysdig.com"
  sysdig_secure_api_token = "01d1debd-933a-4a55-9053-86f6225e2e4f"
}
  
  
