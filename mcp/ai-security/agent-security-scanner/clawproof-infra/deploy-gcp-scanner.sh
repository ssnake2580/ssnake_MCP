#!/bin/bash

# Deploy ClawHub Scanner to Google Cloud VM
# SAFE: Runs in isolated VM that can be destroyed after scan

set -e

# Configuration
PROJECT_ID="${GCP_PROJECT_ID:-your-project-id}"
ZONE="${GCP_ZONE:-us-central1-a}"
MACHINE_TYPE="${GCP_MACHINE_TYPE:-e2-standard-2}"  # 2 vCPU, 8GB RAM
VM_NAME="clawhub-scanner-$(date +%s)"
DISK_SIZE="20GB"

echo "🚀 Deploying ClawHub Scanner to Google Cloud VM"
echo "================================================"
echo "Project: $PROJECT_ID"
echo "Zone: $ZONE"
echo "VM Name: $VM_NAME"
echo ""

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo "❌ Error: gcloud CLI not installed"
    echo "Install: https://cloud.google.com/sdk/docs/install"
    exit 1
fi

# Create startup script
cat > /tmp/scanner-startup.sh <<'EOF'
#!/bin/bash

# Update system
apt-get update
apt-get install -y git curl nodejs npm python3 python3-pip

# Install Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs

# Clone repository (or upload code)
cd /root
git clone https://github.com/sinewaveai/agent-security-scanner-mcp.git scanner
cd scanner

# Install dependencies
npm install
npm install -g clawhub
pip3 install -r requirements.txt --break-system-packages

# Run scan
echo "🛡️  Starting ClawHub scan..."
node index.js scan-clawhub | tee /root/scan-output.log

# Upload results to Cloud Storage (optional)
# gsutil cp clawhub-scan/results.json gs://your-bucket/
# gsutil cp clawhub-scan/report.json gs://your-bucket/

echo "✅ Scan complete! Results in clawhub-scan/"
EOF

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
echo "📊 Monitor progress:"
echo "   gcloud compute ssh $VM_NAME --zone=$ZONE --project=$PROJECT_ID --command='tail -f /root/scan-output.log'"
echo ""
echo "📥 Download results:"
echo "   gcloud compute scp $VM_NAME:/root/scanner/clawhub-scan/results.json ./clawhub-scan/ --zone=$ZONE --project=$PROJECT_ID"
echo "   gcloud compute scp $VM_NAME:/root/scanner/clawhub-scan/report.json ./clawhub-scan/ --zone=$ZONE --project=$PROJECT_ID"
echo ""
echo "🗑️  Delete VM when done:"
echo "   gcloud compute instances delete $VM_NAME --zone=$ZONE --project=$PROJECT_ID --quiet"
echo ""
echo "⏱️  Estimated scan time: 1-2 hours"
echo ""
