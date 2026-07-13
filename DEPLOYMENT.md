# Deploy SecureNet to Google Cloud Run

This project is configured to run as a container on Cloud Run. It is not published by these steps.

## Prerequisites

- A Google Cloud project with billing enabled
- Google Cloud CLI (`gcloud`) installed and authenticated

## Deploy

From this folder, replace `YOUR_PROJECT_ID` and choose a region:

```bash
gcloud config set project YOUR_PROJECT_ID
gcloud run deploy securenet \
  --source . \
  --region asia-south1 \
  --allow-unauthenticated \
  --set-env-vars SECRET_KEY="replace-with-a-long-random-secret"
```

Cloud Run prints the public URL after deployment.

## Important production note

The default SQLite database, generated reports, and email-alert log are stored in Cloud Run's temporary container filesystem. They can be reset whenever an instance restarts. For persistent production data, replace SQLite with Cloud SQL and store reports/logs in Cloud Storage.
