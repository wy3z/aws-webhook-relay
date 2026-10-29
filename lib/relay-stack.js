const path = require("path");
const cdk = require("aws-cdk-lib");
const apigateway = require("aws-cdk-lib/aws-apigateway");
const ec2 = require("aws-cdk-lib/aws-ec2");
const lambda = require("aws-cdk-lib/aws-lambda");
const logs = require("aws-cdk-lib/aws-logs");
const secretsmanager = require("aws-cdk-lib/aws-secretsmanager");

class WebhookRelayStack extends cdk.Stack {
  constructor(scope, id, props = {}) {
    super(scope, id, props);
    const config = props.config;
    let networking = {};
    if (config.vpcEnabled) {
      const vpc = ec2.Vpc.fromVpcAttributes(this, "RelayVpc", {
        vpcId: config.vpcId,
        availabilityZones: config.availabilityZones,
        privateSubnetIds: config.subnetIds,
      });
      const subnets = config.subnetIds.map((subnetId, index) =>
        ec2.Subnet.fromSubnetAttributes(this, `RelaySubnet${index}`, {
          subnetId, availabilityZone: config.availabilityZones[index],
        })
      );
      const securityGroup = ec2.SecurityGroup.fromSecurityGroupId(
        this, "RelaySecurityGroup", config.securityGroupId, { mutable: false }
      );
      networking = { vpc, vpcSubnets: { subnets }, securityGroups: [securityGroup] };
      if (config.createSecretsManagerEndpoint) {
        const endpointSecurityGroup = new ec2.SecurityGroup(this, "SecretsEndpointSecurityGroup", {
          vpc, allowAllOutbound: false,
          description: "HTTPS from relay Lambda to Secrets Manager",
        });
        endpointSecurityGroup.addIngressRule(securityGroup, ec2.Port.tcp(443));
        vpc.addInterfaceEndpoint("SecretsManagerEndpoint", {
          service: ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
          subnets: { subnets },
          securityGroups: [endpointSecurityGroup],
          privateDnsEnabled: true,
          open: false,
        });
      }
    }

    let relayConfigSecret;
    if (config.secretArn) {
      relayConfigSecret = secretsmanager.Secret.fromSecretCompleteArn(this, "RelayConfigSecret", config.secretArn);
    } else if (config.secretName) {
      relayConfigSecret = secretsmanager.Secret.fromSecretNameV2(this, "RelayConfigSecret", config.secretName);
    } else {
      relayConfigSecret = new secretsmanager.Secret(this, "RelayConfigSecret", {
        description: "Webhook relay shared secret and target configuration",
        removalPolicy: cdk.RemovalPolicy.RETAIN,
        generateSecretString: {
          secretStringTemplate: JSON.stringify({
            PRIMARY_URL: config.primaryUrl,
            ...(config.secondaryUrl ? { SECONDARY_URL: config.secondaryUrl } : {}),
          }),
          generateStringKey: "SharedSecret",
          excludePunctuation: true,
          passwordLength: 64,
        },
      });
    }
    const relayFunction = new lambda.Function(this, "RelayFunction", {
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: "index.handler",
      code: lambda.Code.fromAsset(path.join(__dirname, "../lambda")),
      timeout: cdk.Duration.seconds(config.timeoutSeconds),
      memorySize: config.memorySize,
      logGroup: new logs.LogGroup(this, "RelayFunctionLogs", {
        retention: config.logRetentionDays,
        removalPolicy: cdk.RemovalPolicy.RETAIN,
      }),
      ...networking,
      environment: {
        RELAY_CONFIG_SECRET_NAME: relayConfigSecret.secretArn,
        RELAY_TIMEOUT_MS: String(config.forwardTimeoutMs),
        RELAY_FILTER_RULES: JSON.stringify(config.filterRules),
        RELAY_FILTER_TARGETS: JSON.stringify(config.filterTargets),
      },
    });
    relayConfigSecret.grantRead(relayFunction);

    const api = new apigateway.RestApi(this, "RelayApi", {
      description: "Public endpoint for signed upstream webhooks",
      cloudWatchRole: false,
      binaryMediaTypes: ["*/*"],
      deployOptions: {
        throttlingRateLimit: config.rateLimit,
        throttlingBurstLimit: config.burstLimit,
      },
    });
    api.root.addResource("hook").addMethod("POST", new apigateway.LambdaIntegration(relayFunction));
    new cdk.CfnOutput(this, "RelayHookUrl", { value: `${api.url}hook` });
    new cdk.CfnOutput(this, "RelayConfigSecretName", { value: relayConfigSecret.secretName });
    new cdk.CfnOutput(this, "RelayLogGroupName", { value: relayFunction.logGroup.logGroupName });
  }
}

module.exports = { WebhookRelayStack };
