#!/bin/bash
# VibeGuard deployment script
# Usage:
#   ./scripts/deploy.sh          — Lambda 코드 + Step Functions 업데이트
#   ./scripts/deploy.sh --infra  — 위 + CloudFormation 인프라 변경까지 반영

set -e

REGION="us-east-1"
ACCOUNT_ID="233060639373"
STACK_NAME="vibe-guard"
STATE_MACHINE_ARN="arn:aws:states:${REGION}:${ACCOUNT_ID}:stateMachine:vibe-guard-workflow"
BUILD_IMAGE="public.ecr.aws/sam/build-python3.12:latest"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Lambda 함수 목록: "디렉토리:함수이름"
LAMBDAS=(
  "webhook_validator:vibe-guard-webhook-validator"
  "pr_collector:vibe-guard-pr-collector"
  "relevance_filter:vibe-guard-relevance-filter"
  "context_collector:vibe-guard-context-collector"
  "regression_detector:vibe-guard-regression-detector"
  "bedrock_reviewer:vibe-guard-bedrock-reviewer"
  "semgrep_scanner:vibe-guard-semgrep-scanner"
  "result_builder:vibe-guard-result-builder"
  "github_commenter:vibe-guard-github-commenter"
)

# ── 인프라 변경 (--infra 플래그 시에만, Lambda 코드 배포보다 먼저) ───────────
if [[ "$1" == "--infra" ]]; then
  echo "▶ CloudFormation 인프라 배포 중..."
  cd "$ROOT_DIR/infrastructure"
  sam build --use-container --template-file template.yaml
  sam deploy --template-file template.yaml
  cd "$ROOT_DIR"
fi

# ── Lambda 코드 배포 ──────────────────────────────────────────────────────────
echo "▶ Lambda 코드 배포 중..."

for entry in "${LAMBDAS[@]}"; do
  dir="${entry%%:*}"
  name="${entry##*:}"
  lambda_dir="$ROOT_DIR/lambdas/$dir"
  build_dir=$(mktemp -d)

  echo "  • $name 빌드 중..."

  cp "$lambda_dir/handler.py" "$build_dir/"

  req_file="$lambda_dir/requirements.txt"
  if [ -f "$req_file" ] && grep -qv '^#' "$req_file" 2>/dev/null && [ -s "$req_file" ]; then
    docker run --rm \
      --platform linux/amd64 \
      -v "$build_dir":/out \
      -v "$lambda_dir":/src \
      "$BUILD_IMAGE" \
      pip install -r /src/requirements.txt -t /out --quiet --no-cache-dir

    if grep -q '^cryptography' "$req_file" && ! find "$build_dir/cryptography/hazmat/bindings" -name '_rust*.so' -type f | grep -q .; then
      echo "ERROR: $name build is missing cryptography's native _rust extension." >&2
      echo "       The package would fail in Lambda with Runtime.ImportModuleError." >&2
      exit 1
    fi
  fi

  zip_file="/tmp/vibe-guard-${dir}.zip"
  (cd "$build_dir" && zip -r "$zip_file" . -q)

  aws lambda update-function-code \
    --function-name "$name" \
    --zip-file "fileb://$zip_file" \
    --region "$REGION" \
    --query 'FunctionArn' \
    --output text

  rm -rf "$build_dir" "$zip_file"
done

# ── Step Functions ASL 업데이트 ───────────────────────────────────────────────
echo "▶ Step Functions ASL 업데이트 중..."

ASL=$(cat "$ROOT_DIR/step_functions/workflow.asl.json" \
  | sed "s|\${PrCollectorArn}|arn:aws:lambda:${REGION}:${ACCOUNT_ID}:function:vibe-guard-pr-collector|g" \
  | sed "s|\${RelevanceFilterArn}|arn:aws:lambda:${REGION}:${ACCOUNT_ID}:function:vibe-guard-relevance-filter|g" \
  | sed "s|\${ContextCollectorArn}|arn:aws:lambda:${REGION}:${ACCOUNT_ID}:function:vibe-guard-context-collector|g" \
  | sed "s|\${RegressionDetectorArn}|arn:aws:lambda:${REGION}:${ACCOUNT_ID}:function:vibe-guard-regression-detector|g" \
  | sed "s|\${BedrockReviewerArn}|arn:aws:lambda:${REGION}:${ACCOUNT_ID}:function:vibe-guard-bedrock-reviewer|g" \
  | sed "s|\${SemgrepScannerArn}|arn:aws:lambda:${REGION}:${ACCOUNT_ID}:function:vibe-guard-semgrep-scanner|g" \
  | sed "s|\${ResultBuilderArn}|arn:aws:lambda:${REGION}:${ACCOUNT_ID}:function:vibe-guard-result-builder|g" \
  | sed "s|\${GithubCommenterArn}|arn:aws:lambda:${REGION}:${ACCOUNT_ID}:function:vibe-guard-github-commenter|g")

aws stepfunctions update-state-machine \
  --state-machine-arn "$STATE_MACHINE_ARN" \
  --definition "$ASL" \
  --region "$REGION" \
  --query 'updateDate' \
  --output text

echo "✅ 배포 완료"
