# Roadmap

1. Implementation of Tower services:
    * CORS  
    * Compression (zstd with gzip as backup)  
    * Rate limiting  
    * Authentication (especially JWT, Bearer, OAuth, and API Key/Basic Authentication)
        * Usage of argon2id (as specifically recommended by OWASP)  
    * Session  
    * Tracing (already added)  
    * Metrics (OpenTelemetry and Tracing)  
    * Retry  
    * Timeout

2. Documentation  
    * Docs  
    * Swagger/OpenAPI
3. Testing  
    * Unit Testing  
    * Integration Testing
4. Miscellaneous  
    * Audit Logs  
        * Website Audit (what browser was used)  
        * Operation Audit (what operation was performed, who changed what, and what changed)  
    * Environment File  
        * Symlinked .env file  
        * .env file in the .gitignore file (already done)  
        * .env in private, secure, external version control
