import * as pulumi from "@pulumi/pulumi";
import * as gcp from "@pulumi/gcp";

const gcpCfg = new pulumi.Config("gcp");
const project = gcpCfg.require("project");
const region = gcpCfg.require("region");
const stack = pulumi.getStack();

const cfg = new pulumi.Config();
const deployCloudRun = cfg.getBoolean("deployCloudRun") ?? false;
const ingestToken = cfg.requireSecret("ingestToken");

// ---------- Artifact Registry (Docker) ----------
const repoId = `fog-${stack}`;
const arRepo = new gcp.artifactregistry.Repository("artifactRepo", {
  location: region,
  repositoryId: repoId,
  format: "DOCKER",
  description: "Docker repo for cloud-api images",
});

// ---------- Service Account for Cloud Run ----------
const cloudApiSa = new gcp.serviceaccount.Account("cloudApiSa", {
  accountId: `cloud-api-sa-${stack}`.slice(0, 30),
  displayName: `cloud-api SA (${stack})`,
});

new gcp.projects.IAMMember("cloudApiArtifactReader", {
  project,
  role: "roles/artifactregistry.reader",
  member: pulumi.interpolate`serviceAccount:${cloudApiSa.email}`,
});
// IAM: Firestore + Secret read
new gcp.projects.IAMMember("cloudApiDatastoreUser", {
  project,
  role: "roles/datastore.user",
  member: pulumi.interpolate`serviceAccount:${cloudApiSa.email}`,
});

new gcp.projects.IAMMember("cloudApiSecretAccessor", {
  project,
  role: "roles/secretmanager.secretAccessor",
  member: pulumi.interpolate`serviceAccount:${cloudApiSa.email}`,
});

// ---------- Secret Manager: ingest token ----------
const ingestSecret = new gcp.secretmanager.Secret("ingestTokenSecret", {
  secretId: `ingest-token-${stack}`,
  replication: { auto: {} }, // <-- correcto
});

new gcp.secretmanager.SecretVersion("ingestTokenSecretVersion", {
  secret: ingestSecret.id, // OK
  secretData: ingestToken,
});

// ---------- Web bucket (public) ----------
const webBucket = new gcp.storage.Bucket("webBucket", {
  name: `${project}-${stack}-web`,
  location: region,
  uniformBucketLevelAccess: true,
  website: { mainPageSuffix: "index.html" },
  cors: [
    {
      origins: ["*"],                 // <-- correcto
      methods: ["GET", "HEAD", "OPTIONS"],
      responseHeaders: ["Content-Type"], // <-- correcto
      maxAgeSeconds: 3600,
    },
  ],
});

new gcp.storage.BucketIAMMember("webBucketPublicRead", {
  bucket: webBucket.name,
  role: "roles/storage.objectViewer",
  member: "allUsers",
});

// ---------- Optional: Cloud Run (off by default) ----------
let cloudRunUrl: pulumi.Output<string> | undefined = undefined;

if (deployCloudRun) {
  const cloudApiImage = cfg.require("cloudApiImage");

  const svc = new gcp.cloudrunv2.Service("cloudApiService", {
    name: `cloud-api-${stack}`,
    location: region,
    ingress: "INGRESS_TRAFFIC_ALL",
    template: {
      serviceAccount: cloudApiSa.email,
      containers: [
        {
          image: cloudApiImage,
          ports: { containerPort: 8080 }, // <-- correcto (no array)
          envs: [
            { name: "GCP_PROJECT", value: project },
            { name: "STORE_MODE", value: "firestore" },
            { name: "FIRESTORE_ALERTS_COLLECTION", value: "alerts" },
            { name: "FIRESTORE_SUMMARIES_COLLECTION", value: "summaries_10s" },
            {
              name: "INGEST_TOKEN",
              valueSource: {
                secretKeyRef: {
                  secret: ingestSecret.secretId,
                  version: "latest",
                },
              },
            },
          ],
        },
      ],
    },
    traffics: [{ percent: 100, type: "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST" }],
  });

  new gcp.cloudrunv2.ServiceIamMember("cloudApiPublicInvoker", {
    name: svc.name,
    location: region,
    role: "roles/run.invoker",
    member: "allUsers",
  });

  cloudRunUrl = svc.uri;
}

// ---------- Outputs ----------
export const gcpProject = project;
export const gcpRegion = region;

export const artifactRepoUrl = pulumi.interpolate`${region}-docker.pkg.dev/${project}/${arRepo.repositoryId}`;
export const ingestSecretId = ingestSecret.secretId;

export const webBucketName = webBucket.name;
export const webBucketUrl = pulumi.interpolate`https://storage.googleapis.com/${webBucket.name}/index.html`;

export const cloudApiUrl = cloudRunUrl;
