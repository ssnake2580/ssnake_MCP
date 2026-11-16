#!/bin/bash

# Deploy ClawHub FULL Implementation Scanner to Google Cloud VM
# This scans actual source code (GitHub + npm), not just SKILL.md files

set -e

# Configuration
PROJECT_ID="${GCP_PROJECT_ID:-your-project-id}"
ZONE="${GCP_ZONE:-us-central1-a}"
MACHINE_TYPE="${GCP_MACHINE_TYPE:-e2-standard-4}"  # 4 vCPU, 16GB RAM for faster scanning
VM_NAME="clawhub-full-scan-$(date +%s)"
DISK_SIZE="50GB"  # Need more space for source code
BUCKET_NAME="${GCP_BUCKET:-clawhub-scan-results}"

echo "🚀 Deploying ClawHub FULL Implementation Scanner to GCP"
echo "========================================================"
echo "Project: $PROJECT_ID"
echo "Zone: $ZONE"
echo "Machine: $MACHINE_TYPE"
echo "VM Name: $VM_NAME"
echo "Strategy: GitHub clone + npm pack (NO code execution)"
echo ""

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo "❌ Error: gcloud CLI not installed"
    echo "Install: https://cloud.google.com/sdk/docs/install"
    exit 1
fi

# Create GCS bucket for results (if it doesn't exist)
if ! gsutil ls -b gs://$BUCKET_NAME &> /dev/null; then
    echo "📦 Creating GCS bucket: $BUCKET_NAME"
    gsutil mb -p $PROJECT_ID -c STANDARD -l us-central1 gs://$BUCKET_NAME || echo "Bucket already exists or creation failed, continuing..."
fi

# Create startup script
cat > /tmp/scanner-startup.sh <<'EOF'
#!/bin/bash

set -e

echo "🛡️  ClawHub Full Implementation Scanner - Starting Setup"
echo "==========================================================="

# Update system
apt-get update
apt-get install -y git curl wget build-essential python3 python3-pip

# Install Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs

# Install clawhub CLI
npm install -g clawhub

# Clone scanner repository
cd /root
git clone https://github.com/sinewaveai/agent-security-scanner-mcp.git scanner || \
  git clone https://github.com/your-org/agent-security-scanner-mcp.git scanner
cd scanner

# Install dependencies
npm install
pip3 install -r requirements.txt 2>&1 || pip3 install --user -r requirements.txt || echo "Python deps may have issues, continuing..."

# Run the full scan
echo ""
echo "🔍 Starting FULL implementation scan..."
echo "This will take 3-5 hours for ~415 skills"
echo ""

node src/cli/scan-clawhub-full.js 2>&1 | tee /root/scan-output.log

# Upload results to Cloud Storage
echo ""
echo "📤 Uploading results to Cloud Storage..."
gsutil cp -r clawhub-scan-full/* gs://BUCKET_NAME/scan-$(date +%Y%m%d-%H%M%S)/ || true
gsutil cp /root/scan-output.log gs://BUCKET_NAME/scan-output-$(date +%Y%m%d-%H%M%S).log || true

echo ""
echo "✅ Scan complete! Results uploaded to gs://BUCKET_NAME/"
echo ""
echo "🗑️  Remember to delete this VM to avoid charges:"
echo "   gcloud compute instances delete VM_NAME --zone=ZONE --project=PROJECT_ID --quiet"
echo ""

# Optional: Auto-shutdown after scan
# shutdown -h now
EOF

# Replace placeholders in startup script
sed -i '' "s/BUCKET_NAME/$BUCKET_NAME/g" /tmp/scanner-startup.sh
sed -i '' "s/VM_NAME/$VM_NAME/g" /tmp/scanner-startup.sh
sed -i '' "s/ZONE/$ZONE/g" /tmp/scanner-startup.sh
sed -i '' "s/PROJECT_ID/$PROJECT_ID/g" /tmp/scanner-startup.sh

# Create firewall rule to block outbound connections after setup (optional)
# gcloud compute firewall-rules create clawhub-scanner-egress-deny \
#     --direction=EGRESS \
#     --priority=1000 \
#     --network=default \
#     --action=DENY \
#     --rules=all \
#     --target-tags=clawhub-scanner

# Create VM
echo "📦 Creating VM instance..."
gcloud compute instances create "$VM_NAME" \
    --project="$PROJECT_ID" \
    --zone="$ZONE" \
    --machine-type="$MACHINE_TYPE" \
    --boot-disk-size="$DISK_SIZE" \
    --boot-disk-type="pd-standard" \
    --image-family="ubuntu-2204-lts" \
    --image-project="ubuntu-os-cloud" \
    --metadata-from-file=startup-script=/tmp/scanner-startup.sh \
    --scopes="https://www.googleapis.com/auth/cloud-platform" \
    --tags="clawhub-scanner"

echo ""
echo "✅ VM created successfully!"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 Monitoring & Access"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🔍 Monitor progress:"
echo "   gcloud compute ssh $VM_NAME --zone=$ZONE --project=$PROJECT_ID --command='tail -f /root/scan-output.log'"
echo ""
echo "🖥️  SSH into VM:"
echo "   gcloud compute ssh $VM_NAME --zone=$ZONE --project=$PROJECT_ID"
echo ""
echo "📥 Download results (after scan completes):"
echo "   gsutil -m cp -r gs://$BUCKET_NAME/scan-* ./clawhub-scan-full/"
echo ""
echo "🗑️  Delete VM (IMPORTANT - avoid charges):"
echo "   gcloud compute instances delete $VM_NAME --zone=$ZONE --project=$PROJECT_ID --quiet"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "⏱️  Estimated Timeline"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  VM Setup:          5-10 minutes"
echo "  Skill Metadata:    10-15 minutes"
echo "  Source Download:   60-90 minutes  (GitHub + npm)"
echo "  Security Scanning: 90-120 minutes (AST + taint)"
echo "  ────────────────────────────────────────────"
echo "  Total:             3-4 hours"
echo ""
echo "💰 Estimated Cost: ~$0.80 (e2-standard-4 preemptible)"
echo ""
echo "🎯 Expected Results:"
echo "  - 415 skills scanned"
echo "  - 300+ with GitHub/npm source (70-80%)"
echo "  - 60-100 vulnerable skills (15-25%)"
echo "  - Comprehensive security grades (A-F)"
echo ""