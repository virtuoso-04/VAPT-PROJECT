import os
from pathlib import Path
from typing import List, Dict
import random
from transformers import GPT2LMHeadModel, GPT2Tokenizer
import torch
from datetime import datetime

class FakeFileGenerator:
    def __init__(self, model_name: str = "gpt2"):
        self.tokenizer = GPT2Tokenizer.from_pretrained(model_name)
        self.model = GPT2LMHeadModel.from_pretrained(model_name)
        
        # Set padding token if not already set
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token
            
        self.static_dir = Path("app/static")
        self.static_dir.mkdir(parents=True, exist_ok=True)
        
        # Enhanced templates with more sophisticated content
        self.templates = {
            "financial": [
                "Q{quarter} {year} Financial Report\n\nRevenue: ${amount}M\nExpenses: ${amount}M\nNet Profit: ${amount}M\n\nKey Metrics:\n- Customer Acquisition Cost: ${amount}\n- Monthly Recurring Revenue: ${amount}M\n- Churn Rate: {percentage}%\n\nStrategic Initiatives:\n{text}",
                "Project Budget {year}\n\nTotal Budget: ${amount}M\nAllocated Resources:\n- Development: ${amount}M\n- Marketing: ${amount}M\n- Operations: ${amount}M\n\nRisk Assessment:\n{text}",
                "CONFIDENTIAL - Financial Audit Report {year}\n\nExecutive Summary:\n{text}\n\nRevenue Analysis:\n- Q1: ${amount}M\n- Q2: ${amount}M\n- Q3: ${amount}M\n- Q4: ${amount}M\n\nCredit Card Processing:\n- Merchant ID: 4532-{amount}\n- API Key: sk_live_{random_string}\n- Daily Volume: ${amount}K transactions"
            ],
            "technical": [
                "System Architecture Document\n\nInfrastructure Overview:\n{text}\n\nSecurity Measures:\n- Encryption: {text}\n- Access Control: {text}\n- Monitoring: {text}\n\nDeployment Strategy:\n{text}",
                "API Documentation v{version}\n\nEndpoints:\n{text}\n\nAuthentication:\n{text}\n\nRate Limiting:\n{text}",
                "INTERNAL - Database Credentials\n\nProduction Database:\n- Host: prod-db-{amount}.company.com\n- Username: admin_{random_string}\n- Password: P@ssw0rd{amount}!\n- Port: 5432\n\nAPI Keys:\n- AWS Access Key: AKIA{random_string}\n- AWS Secret: {random_string}\n- Redis Password: redis_{amount}_{random_string}"
            ],
            "hr": [
                "Employee Compensation Plan {year}\n\nSalary Bands:\n{text}\n\nBenefits Package:\n{text}\n\nPerformance Metrics:\n{text}",
                "Organizational Structure\n\nDepartment Overview:\n{text}\n\nReporting Lines:\n{text}\n\nKey Personnel:\n{text}",
                "CONFIDENTIAL - Employee Database Export\n\nEmployee Records ({year}):\n{text}\n\nSSN Database:\n- John Smith: 123-45-{amount}\n- Mary Johnson: 987-65-{amount}\n- David Wilson: 555-44-{amount}\n\nSalary Information:\n- CEO: ${amount}K annually\n- CTO: ${amount}K annually\n- Engineering Team: ${amount}K average"
            ],
            "security": [
                "Security Audit Report {year}\n\nVulnerability Assessment:\n{text}\n\nCritical Findings:\n- Unpatched Systems: {amount}\n- Open Ports: {amount}\n- Weak Passwords: {percentage}%\n\nPenetration Test Results:\n{text}",
                "CLASSIFIED - Network Security Configuration\n\nFirewall Rules:\n{text}\n\nVPN Configuration:\n- Server: vpn.company.com\n- Shared Key: {random_string}\n- Certificate: {random_string}\n\nAdmin Credentials:\n- Username: security_admin\n- Password: Secure{amount}!\n- 2FA Backup Codes: {random_string}"
            ],
            "credentials": [
                "Production Environment Access\n\nDatabase Credentials:\n- MySQL: root/{random_string}\n- PostgreSQL: admin/{random_string}\n- MongoDB: dbadmin/{random_string}\n\nCloud Services:\n- AWS IAM: {random_string}\n- Azure: {random_string}\n- GCP: {random_string}",
                "Service Account Keys\n\nAPI Endpoints:\n{text}\n\nAuthentication Tokens:\n- JWT Secret: {random_string}\n- OAuth Client ID: {random_string}\n- OAuth Client Secret: {random_string}\n\nDatabase Connection Strings:\n- Production: postgresql://user:{random_string}@db.prod.com:5432/maindb\n- Staging: mysql://root:{random_string}@staging-db.com:3306/testdb"
            ]
        }

    def _generate_text(self, prompt: str, max_length: int = 150) -> str:
        """Generate text using the GPT-2 model."""
        inputs = self.tokenizer.encode(prompt, return_tensors="pt", truncation=True, max_length=50)
        attention_mask = torch.ones_like(inputs)
        
        outputs = self.model.generate(
            inputs,
            attention_mask=attention_mask,
            max_length=max_length,
            num_return_sequences=1,
            no_repeat_ngram_size=2,
            do_sample=True,
            temperature=0.8,
            top_p=0.9,
            pad_token_id=self.tokenizer.eos_token_id,
            eos_token_id=self.tokenizer.eos_token_id
        )
        
        # Get only the generated part (excluding the prompt)
        generated_text = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        # Remove the prompt from the beginning
        if generated_text.startswith(prompt):
            generated_text = generated_text[len(prompt):].strip()
        
        return generated_text

    def _generate_random_string(self, length: int = 16) -> str:
        """Generate random string for fake credentials."""
        import string
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def _generate_fake_amount(self) -> str:
        """Generate a realistic-looking financial amount."""
        return f"{random.randint(1, 999):,}"

    def _generate_fake_percentage(self) -> str:
        """Generate a realistic-looking percentage."""
        return f"{random.uniform(0.1, 15.0):.1f}"

    def _generate_honeypot_filename(self, category: str) -> str:
        """Generate enticing filenames that attackers would target."""
        prefixes = {
            "financial": ["financial_report", "budget", "revenue", "expenses", "profit_loss", "bank_statements", "tax_returns", "audit_report"],
            "technical": ["architecture", "api_docs", "system_design", "security_audit", "database_schema", "server_config", "backup_scripts"],
            "hr": ["compensation", "org_structure", "employee_data", "benefits", "performance_reviews", "salary_survey", "termination_list"],
            "security": ["security_scan", "vulnerability_report", "penetration_test", "firewall_config", "incident_response", "threat_assessment"],
            "credentials": ["passwords", "api_keys", "config", "secrets", "env_vars", "service_accounts", "ssh_keys", "certificates"]
        }
        
        suffixes = [
            "_q1", "_q2", "_q3", "_q4", f"_{datetime.now().year}", 
            "_draft", "_final", "_v1", "_v2", "_confidential", "_internal",
            "_backup", "_export", "_dump", "_latest", "_production"
        ]
        extensions = [".txt", ".md", ".doc", ".pdf", ".xlsx", ".csv", ".json", ".xml", ".sql", ".env"]
        
        prefix = random.choice(prefixes[category])
        suffix = random.choice(suffixes)
        extension = random.choice(extensions)
        
        return f"{prefix}{suffix}{extension}"

    def generate_fake_file(self, category: str = None) -> Dict:
        """Generate a fake file with realistic content."""
        if category is None:
            category = random.choice(list(self.templates.keys()))
            
        template = random.choice(self.templates[category])
        filename = self._generate_honeypot_filename(category)
        
        # Replace placeholders with generated content
        content = template.format(
            quarter=random.randint(1, 4),
            year=datetime.now().year,
            amount=self._generate_fake_amount(),
            percentage=self._generate_fake_percentage(),
            version=f"{random.randint(1, 3)}.{random.randint(0, 9)}",
            text=self._generate_text("Generate realistic business content: "),
            random_string=self._generate_random_string()
        )
        
        # Save the file
        file_path = self.static_dir / filename
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
            
        return {
            "filename": filename,
            "content_type": "text/plain",
            "size": len(content),
            "category": category
        }

    def generate_multiple_files(self, count: int = 5) -> List[Dict]:
        """Generate multiple fake files."""
        return [self.generate_fake_file() for _ in range(count)]