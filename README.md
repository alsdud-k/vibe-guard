# VibeGuard

AWS 기반 GitHub PR 보안 리뷰 서비스. PR이 생성되면 자동으로 변경 코드를 수집하고, 기존 Repository의 보안 구현과 비교해 Security Regression을 탐지한 뒤 결과를 PR Comment로 제공합니다.

## 동작 방식

```
GitHub PR 생성/업데이트
  → GitHub Webhook
  → API Gateway (POST /webhook)
  → webhook-validator Lambda (HMAC 서명 검증)
  → Step Functions Express Workflow
      → pr-collector Lambda (PR Diff + .vibeguard.yml 수집)
      → github-commenter Lambda (PR Comment 등록)
```

## 프로젝트 구조

```
vibe-guard/
├── infrastructure/
│   ├── template.yaml       # SAM 템플릿 (모든 AWS 리소스)
│   ├── samconfig.toml      # sam deploy 기본 설정
│   └── parameters.json
├── lambdas/
│   ├── webhook_validator/  # HMAC 검증 + Step Functions 트리거
│   ├── pr_collector/       # GitHub API — PR diff + .vibeguard.yml
│   └── github_commenter/   # PR Comment 생성/업데이트
├── step_functions/
│   └── workflow.asl.json   # Step Functions 상태 머신 정의
├── tests/
│   └── test_webhook.py
└── .vibeguard.yml          # 샘플 Security Profile
```

## AWS 구성

| 리소스 | 용도 |
|---|---|
| API Gateway | GitHub Webhook 수신 엔드포인트 |
| Lambda × 3 | webhook-validator, pr-collector, github-commenter |
| Step Functions | 분석 파이프라인 오케스트레이션 (Express Workflow) |
| DynamoDB × 2 | 분석 결과 저장, 실행 Lock |
| Secrets Manager | GitHub App Credential 관리 |
| CloudWatch | Lambda 로그, Step Functions 실행 로그 |

## 시작하기

### 사전 준비

- AWS CLI 설치 및 `aws configure` 완료 (리전: us-east-1)
- AWS SAM CLI 설치
- Docker Desktop 설치
- GitHub App 생성 (Permissions: Pull requests Read/Write, Contents Read)

### Secrets Manager에 GitHub App 정보 저장

```bash
aws secretsmanager create-secret \
  --name "vibe-guard/github-app" \
  --region us-east-1 \
  --secret-string '{
    "app_id": "YOUR_APP_ID",
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...",
    "webhook_secret": "YOUR_WEBHOOK_SECRET",
    "installation_id": "YOUR_INSTALLATION_ID"
  }'
```

### 빌드 및 배포

```bash
cd infrastructure

# 빌드 (Docker 컨테이너 사용 — Linux 호환 바이너리 생성)
sam build --template-file template.yaml

# 첫 배포
sam deploy --guided --template-file template.yaml

# 이후 배포
sam deploy --template-file template.yaml
```

배포 완료 후 Outputs에 출력된 `WebhookEndpoint` URL을 GitHub App Webhook URL에 등록합니다.

### .vibeguard.yml (선택)

Repository 루트에 `.vibeguard.yml`을 추가하면 인증 패턴, 보호 경로, 스캔 범위를 명시적으로 설정할 수 있습니다. 없으면 자동 감지 모드로 동작합니다.

```yaml
framework: fastapi
language: python
authentication: jwt

auth_patterns:
  admin: "Depends(require_admin)"
  user: "Depends(get_current_user)"

protected_paths:
  - path: "/admin"
    required_auth: admin
```

### 테스트

```bash
python3 -m unittest tests/test_webhook.py -v
```
