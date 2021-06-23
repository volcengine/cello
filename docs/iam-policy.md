# IAM Policy
Cello需要将以下策略附加到特定的IAM Role（比如`KubernetesNodeRoleForECS`）以获得访问相应OpenAPI的权限。
最终附加了以下策略的IAM Role需要传递给Cello。

仅开启IPv4时：
```json
{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecs:DescribeInstances",
        "ecs:DescribeInstanceTypes"
      ],
      "Resource": [
        "*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "vpc:DescribeNetworkInterfaces",
        "vpc:CreateNetworkInterface",
        "vpc:AttachNetworkInterface",
        "vpc:DescribeNetworkInterfaceAttributes",
        "vpc:DetachNetworkInterface",
        "vpc:DeleteNetworkInterface",
        "vpc:AssignPrivateIpAddresses",
        "vpc:UnassignPrivateIpAddresses",
        "vpc:DescribeSubnets",
        "vpc:DescribeSubnetAttributes"
      ],
      "Resource": [
        "*"
      ]
    }
  ]
}
```
开启IPv6时还需增加以下策略：
```json
{
      "Effect": "Allow",
      "Action": [
        "vpc:AssignIpv6Addresses",
        "vpc:UnassignIpv6Addresses"
      ],
      "Resource": [
        "*"
      ]
    }
```