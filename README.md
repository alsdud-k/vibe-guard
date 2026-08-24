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
      → relevance-filter Lambda (보안 관련성 판정)
          ├─ SKIP  → 분석 건너뜀 (조용히 종료)
          ├─ LOW   → "보안 이슈 없음" Comment
          └─ HIGH/MEDIUM
              → Parallel: context-collector + semgrep-scanner
              → regression-detector Lambda (Rule 기반 Regression 후보 탐지)
              → bedrock-reviewer Lambda (Claude — 최종 보안 판단)
              → result-builder Lambda (Evidence 구조화 + Risk Score)
              → github-commenter Lambda (분석 결과 Comment + DynamoDB 저장)
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
│   ├── relevance_filter/   # 보안 관련성 분류 (HIGH/MEDIUM/LOW/SKIP)
│   ├── context_collector/  # GitHub Contents API — 기존 보안 코드 수집
│   ├── regression_detector/ # Rule 기반 Authorization Regression 후보 탐지
│   ├── bedrock_reviewer/   # Amazon Bedrock (Claude) — 최종 보안 판단
│   ├── semgrep_scanner/    # Semgrep 정적 분석 (현재 stub)
│   ├── result_builder/     # Evidence 구조화 + Risk Score + Comment 렌더링
│   └── github_commenter/   # PR Comment 생성/업데이트 + DynamoDB 저장
├── evaluation/
│   ├── app/                # vibeguard-test-app 기반 코드 (FastAPI)
│   ├── manifest.json       # 30개 테스트 케이스 정의
│   ├── setup_test_repo.py  # 테스트 리포지토리 + 30개 브랜치 자동 생성
│   └── test_runner.py      # E2E 평가 실행 + Precision/Recall/F1 측정
├── scripts/
│   └── deploy.sh           # Lambda 코드 + Step Functions 배포 스크립트
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
| Lambda × 9 | webhook-validator, pr-collector, relevance-filter, context-collector, regression-detector, bedrock-reviewer, semgrep-scanner, result-builder, github-commenter |
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

### 최초 인프라 배포

```bash
cd infrastructure
sam build --template-file template.yaml
sam deploy --guided --template-file template.yaml
```

배포 완료 후 Outputs에 출력된 `WebhookEndpoint` URL을 GitHub App Webhook URL에 등록합니다.

### 코드 배포 (이후)

Lambda 코드 또는 Step Functions ASL 변경 시:

```bash
./scripts/deploy.sh
```

인프라(template.yaml) 변경까지 반영할 때:

```bash
./scripts/deploy.sh --infra
```

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

scan_paths:
  - "backend/"
  - "app/"

exclude_paths:
  - "tests/"
  - "migrations/"
```

### 테스트

```bash
python3 -m unittest tests/test_webhook.py -v
```

## 평가 방법

### 1. 테스트 리포지토리 생성

```bash
# vibeguard-test-app 리포지토리를 GitHub에 먼저 생성(private)한 뒤:
python evaluation/setup_test_repo.py \
  --repo <your-username>/vibeguard-test-app \
  --token <github-pat> \
  [--create]   # API로 repo 자동 생성 시
```

30개 브랜치가 자동으로 push됩니다.

| 카테고리 | 브랜치 수 | 설명 |
|---|---|---|
| Safe | 10 | 정상 변경 (Finding 없어야 함) |
| Authorization Regression | 10 | 인증 누락/약화 |
| Secret Exposure | 5 | 하드코딩 시크릿 |
| Authentication Regression | 3 | 인증 로직 우회 |
| Injection | 2 | SQL/Command injection |

### 2. E2E 평가 실행

```bash
python evaluation/test_runner.py \
  --repo <your-username>/vibeguard-test-app \
  --token <github-pat> \
  --timeout 180 \
  --output evaluation/results/ \
  [--close-prs]
```

### 3. 결과 확인

```
evaluation/results/
├── results.json    # 케이스별 상세 결과
├── metrics.json    # Precision / Recall / F1 / FPR
├── report.md       # 마크다운 리포트
└── latency.csv     # 케이스별 응답 시간
```

## 평가 결과

30개 테스트 케이스 E2E 평가 결과 (2026-08-24 기준):

| 지표 | 값 |
|---|---|
| **Precision** | **1.000** |
| **Recall** | **1.000** |
| **F1 Score** | **1.000** |
| False Positive Rate | 0.000 |
| TP / FP / TN / FN | 20 / 0 / 10 / 0 |
| 평균 응답시간 | 21초 |

### 카테고리별 결과

| 카테고리 | Precision | Recall | F1 |
|---|---|---|---|
| Authentication | 1.000 | 1.000 | **1.000** |
| Injection | 1.000 | 1.000 | **1.000** |
| Authorization | 1.000 | 1.000 | **1.000** |
| Secret | 1.000 | 1.000 | **1.000** |
