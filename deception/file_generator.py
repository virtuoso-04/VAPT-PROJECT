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
        
        # Templates for different types of fake files
        self.templates = {
            "financial": [
                "Q{quarter} {year} Financial Report\n\nRevenue: ${amount}M\nExpenses: ${amount}M\nNet Profit: ${amount}M\n\nKey Metrics:\n- Customer Acquisition Cost: ${amount}\n- Monthly Recurring Revenue: ${amount}M\n- Churn Rate: {percentage}%\n\nStrategic Initiatives:\n{text}",
                "Project Budget {year}\n\nTotal Budget: ${amount}M\nAllocated Resources:\n- Development: ${amount}M\n- Marketing: ${amount}M\n- Operations: ${amount}M\n\nRisk Assessment:\n{text}"
            ],
            "technical": [
                "System Architecture Document\n\nInfrastructure Overview:\n{text}\n\nSecurity Measures:\n- Encryption: {text}\n- Access Control: {text}\n- Monitoring: {text}\n\nDeployment Strategy:\n{text}",
                "API Documentation v{version}\n\nEndpoints:\n{text}\n\nAuthentication:\n{text}\n\nRate Limiting:\n{text}"
            ],
            "hr": [
                "Employee Compensation Plan {year}\n\nSalary Bands:\n{text}\n\nBenefits Package:\n{text}\n\nPerformance Metrics:\n{text}",
                "Organizational Structure\n\nDepartment Overview:\n{text}\n\nReporting Lines:\n{text}\n\nKey Personnel:\n{text}"
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

    def _generate_fake_amount(self) -> str:
        """Generate a realistic-looking financial amount."""
        return f"{random.randint(1, 999):,}"

    def _generate_fake_percentage(self) -> str:
        """Generate a realistic-looking percentage."""
        return f"{random.uniform(0.1, 15.0):.1f}"

    def _generate_filename(self, category: str) -> str:
        """Generate a realistic-looking filename."""
        prefixes = {
            "financial": ["financial_report", "budget", "revenue", "expenses", "profit_loss"],
            "technical": ["architecture", "api_docs", "system_design", "security_audit"],
            "hr": ["compensation", "org_structure", "employee_data", "benefits"]
        }
        
        suffixes = ["_q1", "_q2", "_q3", "_q4", f"_{datetime.now().year}", "_draft", "_final", "_v1", "_v2"]
        extensions = [".txt", ".md", ".doc", ".pdf"]
        
        prefix = random.choice(prefixes[category])
        suffix = random.choice(suffixes)
        extension = random.choice(extensions)
        
        return f"{prefix}{suffix}{extension}"

    def generate_fake_file(self, category: str = None) -> Dict:
        """Generate a fake file with realistic content."""
        if category is None:
            category = random.choice(list(self.templates.keys()))
            
        template = random.choice(self.templates[category])
        filename = self._generate_filename(category)
        
        # Replace placeholders with generated content
        content = template.format(
            quarter=random.randint(1, 4),
            year=datetime.now().year,
            amount=self._generate_fake_amount(),
            percentage=self._generate_fake_percentage(),
            version=f"{random.randint(1, 3)}.{random.randint(0, 9)}",
            text=self._generate_text("Generate realistic business content: ")
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