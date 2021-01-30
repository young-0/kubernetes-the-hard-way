[TOC]

# kubernetes-the-hard-way

## 01. Prerequisites

```
Now 2021-01-22
CentOS Linux release 7.6.1810 (Core) 
Linux VM_0_40_linux 3.10.0-957.21.3.el7.x86_64 
service clusterCIDR: "10.32.0.0/16"
pod clusterCIDR: "10.200.0.0/16"
kubectl: v1.18.6
etcd Version: 3.4.10
```

## 02. Installing the Client Tools

### Install CFSSL

```
wget  \
  https://storage.googleapis.com.cnpmjs.org/kubernetes-the-hard-way/cfssl/1.4.1/linux/cfssl \
  https://storage.googleapis.com.cnpmjs.org/kubernetes-the-hard-way/cfssl/1.4.1/linux/cfssljson;
chmod +x cfssl cfssljson;
sudo mv cfssl cfssljson /usr/local/bin/;

curl -s -L -o /usr/local/bin/cfssl-certinfo https://pkg.cfssl.org/R1.2/cfssl-certinfo_linux-amd64;
chmod +x /usr/local/bin/cfssl-certinfo ;
```

### Install kubectl

```
wget https://storage.googleapis.com.cnpmjs.org/kubernetes-release/release/v1.18.6/bin/linux/amd64/kubectl;
chmod +x kubectl;
sudo mv kubectl /usr/local/bin/;
kubectl version --client;
```

## 03. Provisioning Compute Resources

Kubernetes需要一组机器来托管Kubernetes控制平面和最终运行容器的工作节点。在本实验中，您将配置在单个计算区域上运行安全且高度可用的Kubernetes集群所需的计算资源。

联网

虚拟私有云网络

防火墙规则

Kubernetes公共IP地址

分配一个静态IP地址，该地址将附加到Kubernetes API服务器前面的外部负载均衡器

计算实例
1. 三个Master
2. 三个Worker

这里使用三台主机，做Master及worker。  
IP为 10.0.0.40，10.0.0.45，10.0.0.48。

配置SSH访问

## 04. Provisioning a CA and Generating TLS Certificates

使用CloudFlare的PKI工具包cfssl来配置PKI基础架构，然后使用它来引导证书颁发机构，并为以下组件生成TLS证书：etcd，kube-apiserver，kube-controller-manager，kube-scheduler， kubelet和kube-proxy。

### 证书颁发机构

在本部分中，您将提供一个可用于生成其他TLS证书的证书颁发机构。

生成CA配置文件，证书和私钥：  
（修改证书有效期为10年）

```
cat > ca-config.json <<EOF
{
  "signing": {
    "default": {
      "expiry": "87600h"
    },
    "profiles": {
      "kubernetes": {
        "usages": ["signing", "key encipherment", "server auth", "client auth"],
        "expiry": "87600h"
      }
    }
  }
}
EOF

cat > ca-csr.json <<EOF
{
  "CN": "Kubernetes",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Portland",
      "O": "Kubernetes",
      "OU": "CA",
      "ST": "Oregon"
    }
  ],
  "ca":{
      "expiry":"87600h"
  }
}
EOF

cfssl gencert -initca ca-csr.json | cfssljson -bare ca
```

得到两个文件

```
ca-key.pem
ca.pem
```

### 客户端和服务器证书

为每个Kubernetes组件生成客户端和服务器证书，并为Kubernetes admin用户生成客户端证书。

#### 管理员客户端证书

```

cat > admin-csr.json <<EOF
{
  "CN": "admin",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Portland",
      "O": "system:masters",
      "OU": "Kubernetes The Hard Way",
      "ST": "Oregon"
    }
  ]
}
EOF

cfssl gencert \
  -ca=ca.pem \
  -ca-key=ca-key.pem \
  -config=ca-config.json \
  -profile=kubernetes \
  admin-csr.json | cfssljson -bare admin

```

得到证书

```
admin-key.pem
admin.pem
```

查看证书的有效期

```
cfssl-certinfo -cert admin.pem | grep -E "not_before|not_after"
"not_before": "2021-01-21T07:28:00Z",  
"not_after": "2031-01-19T07:28:00Z"
```

#### Kubelet客户端证书

Kubernetes使用一种称为`Node Authorizer`的专用授权模式，该模式专门授权Kubelets发出的API请求。为了获得节点授权者的授权，Kubelets必须使用将其标识为`system:nodes`组中的凭据，其用户名为`system:node:<nodeName>`。在本部分中，您将为每个满足节点授权者要求的Kubernetes工作节点创建一个证书。

为每个Kubernetes工作者节点生成一个证书和私钥：
(节点实例名使用主机IP代替)

```
for instance in 10.0.0.40 10.0.0.45 10.0.0.48 ; do
cat > ${instance}-csr.json <<EOF
{
  "CN": "system:node:${instance}",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Portland",
      "O": "system:nodes",
      "OU": "Kubernetes The Hard Way",
      "ST": "Oregon"
    }
  ]
}
EOF

cfssl gencert \
  -ca=ca.pem \
  -ca-key=ca-key.pem \
  -config=ca-config.json \
  -hostname=${instance} \
  -profile=kubernetes \
  ${instance}-csr.json | cfssljson -bare ${instance}
done
```

得到以下证书

```
10.0.0.40.pem
10.0.0.40-key.pem
10.0.0.45.pem
10.0.0.45-key.pem
10.0.0.48.pem
10.0.0.48-key.pem
```

验证证书的有效期

```
for instance in 10.0.0.40 10.0.0.45 10.0.0.48 ; do
cfssl-certinfo -cert ${instance}.pem  | grep -E "not_before|not_after"
done
```

#### The Controller Manager Client Certificate

```
cat > kube-controller-manager-csr.json <<EOF
{
  "CN": "system:kube-controller-manager",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Portland",
      "O": "system:kube-controller-manager",
      "OU": "Kubernetes The Hard Way",
      "ST": "Oregon"
    }
  ]
}
EOF

cfssl gencert \
  -ca=ca.pem \
  -ca-key=ca-key.pem \
  -config=ca-config.json \
  -profile=kubernetes \
  kube-controller-manager-csr.json | cfssljson -bare kube-controller-manager

cfssl-certinfo -cert kube-controller-manager.pem | grep -E "not_before|not_after"

```

#### The Kube Proxy Client Certificate

```
cat > kube-proxy-csr.json <<EOF
{
  "CN": "system:kube-proxy",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Portland",
      "O": "system:node-proxier",
      "OU": "Kubernetes The Hard Way",
      "ST": "Oregon"
    }
  ]
}
EOF

cfssl gencert \
  -ca=ca.pem \
  -ca-key=ca-key.pem \
  -config=ca-config.json \
  -profile=kubernetes \
  kube-proxy-csr.json | cfssljson -bare kube-proxy

cfssl-certinfo -cert kube-proxy.pem | grep -E "not_before|not_after"
```

#### The Scheduler Client Certificate

```
cat > kube-scheduler-csr.json <<EOF
{
  "CN": "system:kube-scheduler",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Portland",
      "O": "system:kube-scheduler",
      "OU": "Kubernetes The Hard Way",
      "ST": "Oregon"
    }
  ]
}
EOF

cfssl gencert \
  -ca=ca.pem \
  -ca-key=ca-key.pem \
  -config=ca-config.json \
  -profile=kubernetes \
  kube-scheduler-csr.json | cfssljson -bare kube-scheduler

cfssl-certinfo -cert kube-scheduler.pem | grep -E "not_before|not_after"
```

#### The Kubernetes API Server Certificate

确保静态IP地址，keepalive IP地址，负载均衡内外网IP地址都将被包含在该Kubernetes API服务器证书主题备用名称的列表。这将确保证书可以被远程客户端验证。

生成Kubernetes API Server证书和私钥：

```
KUBERNETES_PUBLIC_ADDRESS=10.0.0.40,10.0.0.45,10.0.0.48

KUBERNETES_HOSTNAMES=kubernetes,kubernetes.default,kubernetes.default.svc,kubernetes.default.svc.cluster,kubernetes.svc.cluster.local

cat > kubernetes-csr.json <<EOF
{
  "CN": "kubernetes",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Portland",
      "O": "Kubernetes",
      "OU": "Kubernetes The Hard Way",
      "ST": "Oregon"
    }
  ]
}
EOF

cfssl gencert \
  -ca=ca.pem \
  -ca-key=ca-key.pem \
  -config=ca-config.json \
  -hostname=10.32.0.1,10.240.0.10,10.240.0.11,10.240.0.12,${KUBERNETES_PUBLIC_ADDRESS},127.0.0.1,${KUBERNETES_HOSTNAMES} \
  -profile=kubernetes \
  kubernetes-csr.json | cfssljson -bare kubernetes
  
cfssl-certinfo -cert kubernetes.pem | grep -E "not_before|not_after"
```

> 将自动为Kubernetes API服务器分配kubernetes内部dns名称，该IP地址为内部集群服务保留的地址范围（10.32.0.0/16）中的第一个IP地址（10.32.0.1）。

得到两个文件

```
kubernetes-key.pem
kubernetes.pem
```

#### The Service Account Key Pair

如管理服务帐户文档中所述，Kubernetes Controller Manager利用密钥对生成和签名服务帐户令牌。

生成服务帐户证书和私钥：

```
cat > service-account-csr.json <<EOF
{
  "CN": "service-accounts",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Portland",
      "O": "Kubernetes",
      "OU": "Kubernetes The Hard Way",
      "ST": "Oregon"
    }
  ]
}
EOF

cfssl gencert \
  -ca=ca.pem \
  -ca-key=ca-key.pem \
  -config=ca-config.json \
  -profile=kubernetes \
  service-account-csr.json | cfssljson -bare service-account
  
cfssl-certinfo -cert service-account.pem | grep -E "not_before|not_after"
```

两个文件

```
service-account-key.pem
service-account.pem
```

#### Distribute the Client and Server Certificates

将适当的证书和私钥复制到每个Worker工作实例：

```
for instance in 10.0.0.40 10.0.0.45 10.0.0.48; do
  scp ca.pem ${instance}-key.pem ${instance}.pem ${instance}:~/
done
```

将适当的证书和私钥复制到每个Master控制器实例：

```
for instance in 10.0.0.40 10.0.0.45 10.0.0.48; do
  scp ca.pem ca-key.pem kubernetes-key.pem kubernetes.pem \
    service-account-key.pem service-account.pem ${instance}:~/
done
```

在kube-proxy，kube-controller-manager，kube-scheduler，和kubelet客户端证书将被用于生成在接下来的实验客户端身份验证的配置文件。

## 05. Generating Kubernetes Configuration Files for Authentication

生成Kubernetes配置文件（也称为kubeconfigs），该文件使Kubernetes客户端可以定位和验证Kubernetes API服务器。

### 客户端身份验证配置

为controller manager, kubelet, kube-proxy, 和 scheduler 以及admin用户生成kubeconfig  文件。

#### Kubernetes公共IP地址

每个kubeconfig都需要连接Kubernetes API服务器。为了支持高可用性，将使用分配给Kubernetes API服务器前面的外部负载均衡器的IP地址。

这里选择一台Master 10.0.0.40，作为负载均衡IP。

KUBERNETES_PUBLIC_ADDRESS=10.0.0.40

#### kubelet Kubernetes配置文件

为Kubelet生成kubeconfig文件时，必须使用与Kubelet的节点名称匹配的客户端证书。这将确保Kubernetes节点授权者正确授权Kubelet 。

上面创建证书时，指定的Kubelet节点名称为主机IP地址 。

以下命令必须在生成SSL证书的目录中运行。

为每个工作节点生成一个kubeconfig文件：

```
KUBERNETES_PUBLIC_ADDRESS=10.0.0.40

for instance in 10.0.0.40 10.0.0.45 10.0.0.48; do
  kubectl config set-cluster kubernetes-the-hard-way \
    --certificate-authority=ca.pem \
    --embed-certs=true \
    --server=https://${KUBERNETES_PUBLIC_ADDRESS}:6443 \
    --kubeconfig=${instance}.kubeconfig

  kubectl config set-credentials system:node:${instance} \
    --client-certificate=${instance}.pem \
    --client-key=${instance}-key.pem \
    --embed-certs=true \
    --kubeconfig=${instance}.kubeconfig

  kubectl config set-context default \
    --cluster=kubernetes-the-hard-way \
    --user=system:node:${instance} \
    --kubeconfig=${instance}.kubeconfig

  kubectl config use-context default --kubeconfig=${instance}.kubeconfig
done
```

得到以下文件

```
10.0.0.40.kubeconfig
10.0.0.45.kubeconfig
10.0.0.48.kubeconfig
```

#### kube-proxy Kubernetes配置文件

为kube-proxy服务生成一个kubeconfig文件：

```
kubectl config set-cluster kubernetes-the-hard-way \
    --certificate-authority=ca.pem \
    --embed-certs=true \
    --server=https://${KUBERNETES_PUBLIC_ADDRESS}:6443 \
    --kubeconfig=kube-proxy.kubeconfig

  kubectl config set-credentials system:kube-proxy \
    --client-certificate=kube-proxy.pem \
    --client-key=kube-proxy-key.pem \
    --embed-certs=true \
    --kubeconfig=kube-proxy.kubeconfig

  kubectl config set-context default \
    --cluster=kubernetes-the-hard-way \
    --user=system:kube-proxy \
    --kubeconfig=kube-proxy.kubeconfig

  kubectl config use-context default --kubeconfig=kube-proxy.kubeconfig
```

kube-proxy.kubeconfig

#### kube-controller-manager Kubernetes配置文件

```
 kubectl config set-cluster kubernetes-the-hard-way \
    --certificate-authority=ca.pem \
    --embed-certs=true \
    --server=https://127.0.0.1:6443 \
    --kubeconfig=kube-controller-manager.kubeconfig

  kubectl config set-credentials system:kube-controller-manager \
    --client-certificate=kube-controller-manager.pem \
    --client-key=kube-controller-manager-key.pem \
    --embed-certs=true \
    --kubeconfig=kube-controller-manager.kubeconfig

  kubectl config set-context default \
    --cluster=kubernetes-the-hard-way \
    --user=system:kube-controller-manager \
    --kubeconfig=kube-controller-manager.kubeconfig

  kubectl config use-context default --kubeconfig=kube-controller-manager.kubeconfig
```

kube-controller-manager.kubeconfig

#### kube-scheduler Kubernetes配置文件

```
  kubectl config set-cluster kubernetes-the-hard-way \
    --certificate-authority=ca.pem \
    --embed-certs=true \
    --server=https://127.0.0.1:6443 \
    --kubeconfig=kube-scheduler.kubeconfig

  kubectl config set-credentials system:kube-scheduler \
    --client-certificate=kube-scheduler.pem \
    --client-key=kube-scheduler-key.pem \
    --embed-certs=true \
    --kubeconfig=kube-scheduler.kubeconfig

  kubectl config set-context default \
    --cluster=kubernetes-the-hard-way \
    --user=system:kube-scheduler \
    --kubeconfig=kube-scheduler.kubeconfig

  kubectl config use-context default --kubeconfig=kube-scheduler.kubeconfig
```

#### 管理员Kubernetes配置文件

为admin用户生成一个kubeconfig文件：

```
  kubectl config set-cluster kubernetes-the-hard-way \
    --certificate-authority=ca.pem \
    --embed-certs=true \
    --server=https://127.0.0.1:6443 \
    --kubeconfig=admin.kubeconfig

  kubectl config set-credentials admin \
    --client-certificate=admin.pem \
    --client-key=admin-key.pem \
    --embed-certs=true \
    --kubeconfig=admin.kubeconfig

  kubectl config set-context default \
    --cluster=kubernetes-the-hard-way \
    --user=admin \
    --kubeconfig=admin.kubeconfig

  kubectl config use-context default --kubeconfig=admin.kubeconfig
```

#### 分发配置文件

```
复制适当的kubelet和kube-proxy kubeconfig文件到每个worker实例：

for instance in 10.0.0.40 10.0.0.45 10.0.0.48; do
  scp ${instance}.kubeconfig kube-proxy.kubeconfig ${instance}:~/
done

复制适当的kube-controller-manager和kube-schedulerkubeconfig文件，每个Master实例：

for instance in 10.0.0.40 10.0.0.45 10.0.0.48; do
  scp admin.kubeconfig kube-controller-manager.kubeconfig kube-scheduler.kubeconfig ${instance}:~/
done
```

## 06. 数据加密密钥

Kubernetes存储各种数据，包括集群状态，应用程序配置和机密。Kubernetes支持静态加密集群数据的功能。

在本实验中，您将生成适合加密Kubernetes Secrets的加密密钥和加密配置。

生成加密密钥：

```
ENCRYPTION_KEY=$(head -c 32 /dev/urandom | base64)
```

创建encryption-config.yaml加密配置文件：

```
cat > encryption-config.yaml <<EOF
kind: EncryptionConfig
apiVersion: v1
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: ${ENCRYPTION_KEY}
      - identity: {}
EOF
```

将encryption-config.yaml加密配置文件复制到每个控制器实例：

```
for instance in 10.0.0.40 10.0.0.45 10.0.0.48; do
  scp encryption-config.yaml ${instance}:~/
done
```

## 07. 引导etcd集群

Kubernetes组件是无状态的，并将集群状态存储在etcd中。在本实验中，您将引导三个节点的etcd群集，并对其进行配置以实现高可用性和安全的远程访问。

### 先决条件

以下命令在三台Master上同时运

### 引导etcd集群成员

- 下载并安装etcd二进制文件

```
wget -q "https://github.com/etcd-io/etcd/releases/download/v3.4.10/etcd-v3.4.10-linux-amd64.tar.gz";
tar -xf etcd-v3.4.10-linux-amd64.tar.gz;
sudo mv etcd-v3.4.10-linux-amd64/etcd* /usr/local/bin/;

```

- 配置etcd服务器

实例内部IP地址将用于服务客户端请求并与etcd群集对等方通信。获取当前计算实例的内部IP地址`INTERNAL_IP`：

每个etcd成员在etcd集群中必须具有唯一的名称。设置etcd名称使用当前计算实例的主机名，这里使用`INTERNAL_IP`：

```
sudo mkdir -p /etc/etcd /var/lib/etcd
sudo chmod 700 /var/lib/etcd
sudo cp /root/{ca.pem,kubernetes-key.pem,kubernetes.pem} /etc/etcd/
INTERNAL_IP=$(ifconfig eth0 | grep -oP '(?<=inet )(\d+\.){3}\d+')
ETCD_NAME=${INTERNAL_IP}
ETCD_CLUSTER="10.0.0.40=https://10.0.0.40:2380,10.0.0.45=https://10.0.0.45:2380,10.0.0.48=https://10.0.0.48:2380"
```

- 创建 systemd unit 文件 `etcd.service`

```
cat <<EOF | sudo tee /etc/systemd/system/etcd.service
[Unit]
Description=etcd
Documentation=https://github.com/coreos

[Service]
Type=notify
ExecStart=/usr/local/bin/etcd \\
  --name ${ETCD_NAME} \\
  --cert-file=/etc/etcd/kubernetes.pem \\
  --key-file=/etc/etcd/kubernetes-key.pem \\
  --peer-cert-file=/etc/etcd/kubernetes.pem \\
  --peer-key-file=/etc/etcd/kubernetes-key.pem \\
  --trusted-ca-file=/etc/etcd/ca.pem \\
  --peer-trusted-ca-file=/etc/etcd/ca.pem \\
  --peer-client-cert-auth \\
  --client-cert-auth \\
  --initial-advertise-peer-urls https://${INTERNAL_IP}:2380 \\
  --listen-peer-urls https://${INTERNAL_IP}:2380 \\
  --listen-client-urls https://${INTERNAL_IP}:2379,http://127.0.0.1:2379 \\
  --advertise-client-urls https://${INTERNAL_IP}:2379 \\
  --initial-cluster-token etcd-cluster-0 \\
  --initial-cluster ${ETCD_CLUSTER} \\
  --initial-cluster-state new \\
  --data-dir=/var/lib/etcd \\
  --enable-v2=true
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

启动etcd服务

```
sudo systemctl daemon-reload
sudo systemctl enable etcd
sudo systemctl start etcd
```

- 验证

```
ETCDCTL_API=3 etcdctl member list   --endpoints=http://127.0.0.1:2379 
```

输出

```
54edef07d0b037aa, started, 10.0.0.40, https://10.0.0.40:2380, https://10.0.0.40:2379, false
e3e16c00ce2576d6, started, 10.0.0.48, https://10.0.0.48:2380, https://10.0.0.48:2379, false
ee17930d1b70d430, started, 10.0.0.45, https://10.0.0.45:2380, https://10.0.0.45:2379, false
```

## 08. 引导k8s控制平面

在本实验中，您将跨三个计算实例引导Kubernetes控制平面，并对其进行配置以实现高可用性。您还将创建一个外部负载平衡器，以将Kubernetes API服务器公开给远程客户端。  
以下组件将安装在每个节点上：Kubernetes API服务器API Server，调度程序Scheduler和控制器管理器Controller Manager。

登陆每个Master实例，在每个实例上执行以下命令

### 下载安装二进制文件

```
sudo mkdir -p /etc/kubernetes/config;
wget -q  \
  "https://storage.googleapis.com.cnpmjs.org/kubernetes-release/release/v1.18.6/bin/linux/amd64/kube-apiserver" \
  "https://storage.googleapis.com.cnpmjs.org/kubernetes-release/release/v1.18.6/bin/linux/amd64/kube-controller-manager" \
  "https://storage.googleapis.com.cnpmjs.org/kubernetes-release/release/v1.18.6/bin/linux/amd64/kube-scheduler" \
  "https://storage.googleapis.com.cnpmjs.org/kubernetes-release/release/v1.18.6/bin/linux/amd64/kubectl";

chmod +x kube-apiserver kube-controller-manager kube-scheduler kubectl;
sudo mv kube-apiserver kube-controller-manager kube-scheduler kubectl /usr/local/bin/;

```

内核参数设置

```
yum install -y ipvsadm  ipset  conntrack-tools
modprobe br_netfilter
echo "/usr/sbin/modprobe br_netfilter" >> /etc/rc.local
chmod +x /etc/rc.d/rc.local

cat << EOF | sudo tee /etc/sysctl.conf
# For more information, see sysctl.conf(5) and sysctl.d(5).
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

vm.swappiness = 0
net.ipv4.neigh.default.gc_stale_time=120
net.ipv4.ip_forward = 1

# see details in https://help.aliyun.com/knowledge_detail/39428.html
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
net.ipv4.conf.default.arp_announce = 2
net.ipv4.conf.lo.arp_announce=2
net.ipv4.conf.all.arp_announce=2


# see details in https://help.aliyun.com/knowledge_detail/41334.html
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 1024
net.ipv4.tcp_synack_retries = 2
kernel.sysrq = 1

#iptables透明网桥的实现
# NOTE: kube-proxy 要求 NODE 节点操作系统中要具备 /sys/module/br_netfilter 文件，
# 而且还要设置 bridge-nf-call-iptables=1，如果不满足要求，那么 kube-proxy 只是将检查信息记录到日志中，
# kube-proxy 仍然会正常运行，但是这样通过 Kube-proxy 设置的某些 iptables 规则就不会工作。

net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-arptables = 1

# Do not accept source routing
net.ipv4.conf.default.accept_source_route = 0

# Controls the System Request debugging functionality of the kernel

# Controls whether core dumps will append the PID to the core filename.
# Useful for debugging multi-threaded applications.
kernel.core_uses_pid = 1

# Controls the maximum size of a message, in bytes
kernel.msgmnb = 65536

# Controls the default maxmimum size of a mesage queue
kernel.msgmax = 65536

net.ipv4.conf.all.promote_secondaries = 1
net.ipv4.conf.default.promote_secondaries = 1
net.ipv6.neigh.default.gc_thresh3 = 4096
net.ipv4.neigh.default.gc_thresh3 = 4096

kernel.softlockup_panic = 1
kernel.shmmax=68719476736
kernel.printk = 5
kernel.numa_balancing = 0
EOF

sysctl -p
```


### 配置Kubernetes API服务器

```
sudo mkdir -p /var/lib/kubernetes/
cd /root/
sudo mv ca.pem ca-key.pem kubernetes-key.pem kubernetes.pem \
service-account-key.pem service-account.pem \
encryption-config.yaml /var/lib/kubernetes/
```

实例内部IP地址将用于将API Server通告给群集的成员。检索当前计算实例的内部IP地址：

```
INTERNAL_IP=$(ifconfig eth0 | grep -oP '(?<=inet )(\d+\.){3}\d+')
ETCD_SERVER="https://10.0.0.40:2379,https://10.0.0.45:2379,https://10.0.0.48:2379"
```

创建system unit文件kube-apiserver.service：

``` bash
cat <<EOF | sudo tee /etc/systemd/system/kube-apiserver.service
[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/kubernetes/kubernetes

[Service]
ExecStart=/usr/local/bin/kube-apiserver \\
  --advertise-address=${INTERNAL_IP} \\
  --allow-privileged=true \\
  --apiserver-count=3 \\
  --audit-log-maxage=30 \\
  --audit-log-maxbackup=3 \\
  --audit-log-maxsize=100 \\
  --audit-log-path=/var/log/audit.log \\
  --authorization-mode=Node,RBAC \\
  --runtime-config=api/all=true,extensions/v1beta1/deployments=true,extensions/v1beta1/daemonsets=true \\
  --bind-address=0.0.0.0 \\
  --client-ca-file=/var/lib/kubernetes/ca.pem \\
  --enable-admission-plugins=NamespaceLifecycle,NodeRestriction,LimitRanger,ServiceAccount,DefaultStorageClass,ResourceQuota \\
  --etcd-cafile=/var/lib/kubernetes/ca.pem \\
  --etcd-certfile=/var/lib/kubernetes/kubernetes.pem \\
  --etcd-keyfile=/var/lib/kubernetes/kubernetes-key.pem \\
  --etcd-servers=${ETCD_SERVER} \\
  --event-ttl=1h \\
  --encryption-provider-config=/var/lib/kubernetes/encryption-config.yaml \\
  --kubelet-certificate-authority=/var/lib/kubernetes/ca.pem \\
  --kubelet-client-certificate=/var/lib/kubernetes/kubernetes.pem \\
  --kubelet-client-key=/var/lib/kubernetes/kubernetes-key.pem \\
  --kubelet-https=true \\
  --service-account-key-file=/var/lib/kubernetes/service-account.pem \\
  --service-cluster-ip-range=10.32.0.0/16 \\
  --service-node-port-range=30000-32767 \\
  --tls-cert-file=/var/lib/kubernetes/kubernetes.pem \\
  --tls-private-key-file=/var/lib/kubernetes/kubernetes-key.pem \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

### 配置Kubernetes Controller Manager

拷贝 `kube-controller-manager kubeconfig`配置文件到指定位置，创建系统unit文件

```
sudo mv kube-controller-manager.kubeconfig /var/lib/kubernetes/

cat <<EOF | sudo tee /etc/systemd/system/kube-controller-manager.service
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/kubernetes/kubernetes

[Service]
ExecStart=/usr/local/bin/kube-controller-manager \\
  --bind-address=0.0.0.0 \\
  --cluster-cidr=10.200.0.0/16 \\
  --cluster-name=kubernetes \\
  --cluster-signing-cert-file=/var/lib/kubernetes/ca.pem \\
  --cluster-signing-key-file=/var/lib/kubernetes/ca-key.pem \\
  --kubeconfig=/var/lib/kubernetes/kube-controller-manager.kubeconfig \\
  --leader-elect=true \\
  --root-ca-file=/var/lib/kubernetes/ca.pem \\
  --service-account-private-key-file=/var/lib/kubernetes/service-account-key.pem \\
  --service-cluster-ip-range=10.32.0.0/16 \\
  --node-cidr-mask-size=24 \\
  --use-service-account-credentials=true \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

### 配置 Kubernetes Scheduler

拷贝配置文件到指定位置，创建系统unit文件

```
sudo mv kube-scheduler.kubeconfig /var/lib/kubernetes/

cat <<EOF | sudo tee /etc/kubernetes/config/kube-scheduler.yaml
apiVersion: kubescheduler.config.k8s.io/v1alpha1
kind: KubeSchedulerConfiguration
clientConnection:
  kubeconfig: "/var/lib/kubernetes/kube-scheduler.kubeconfig"
leaderElection:
  leaderElect: true
EOF


cat <<EOF | sudo tee /etc/systemd/system/kube-scheduler.service
[Unit]
Description=Kubernetes Scheduler
Documentation=https://github.com/kubernetes/kubernetes

[Service]
ExecStart=/usr/local/bin/kube-scheduler \\
  --config=/etc/kubernetes/config/kube-scheduler.yaml \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

启动

```
systemctl daemon-reload
systemctl enable kube-apiserver kube-controller-manager kube-scheduler
systemctl start kube-apiserver kube-controller-manager kube-scheduler
```

### 启用HTTP运行状况检查

Google网络负载平衡器将用于流量分配在三个API服务器，并允许每个API服务器TLS终端连接，并验证客户端证书。  
网络负载平衡器仅支持HTTP运行状况检查，这意味着无法使用API服务器公开的HTTPS端点。  
解决方法是，nginx Web服务器可用于代理HTTP运行状况检查。  
在本节中，将安装nginx并将其配置为接受端口上的HTTP运行状况检查，80并通过代理与API服务器的连接https://127.0.0.1:6443/healthz。

默认情况下，API服务器端点/healthz不需要身份验证。

忽略

### 验证

查看组件状态

```
# kubectl  get cs --kubeconfig admin.kubeconfig
NAME                 STATUS    MESSAGE             ERROR
controller-manager   Healthy   ok                  
scheduler            Healthy   ok                  
etcd-1               Healthy   {"health":"true"}   
etcd-0               Healthy   {"health":"true"}   
etcd-2               Healthy   {"health":"true"} 
```

### 配置 Kubelet RBAC 认证

在本部分中，您将配置RBAC权限，以允许Kubernetes API服务器访问每个工作程序节点上的Kubelet API。  
需要访问Kubelet API才能检索指标，日志和在pod中执行命令。

本教程将Kubelet `--authorization-mode`标志设置为`Webhook`。Webhook模式使用`SubjectAccessReview API`来确定授权。

本节中的命令将影响整个集群，并且**仅需从一个控制器节点运行一次**。

登陆其中一台Master

创建`system:kube-apiserver-to-kubelet` ClusterRole有权限访问Kubelet API，并执行与管理相关的pod最常见的任务：

```
cat <<EOF | kubectl apply --kubeconfig admin.kubeconfig -f -
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRole
metadata:
  annotations:
    rbac.authorization.kubernetes.io/autoupdate: "true"
  labels:
    kubernetes.io/bootstrapping: rbac-defaults
  name: system:kube-apiserver-to-kubelet
rules:
  - apiGroups:
      - ""
    resources:
      - nodes/proxy
      - nodes/stats
      - nodes/log
      - nodes/spec
      - nodes/metrics
    verbs:
      - "*"
EOF
```

Kubernetes API服务器使用`--kubelet-client-certificate`标志定义的客户端证书以`kubernetes`用户身份向Kubelet进行身份验证。

将`system：kube-apiserver-to-kubelet` ClusterRole绑定到kubernetes用户：

```
cat <<EOF | kubectl apply --kubeconfig admin.kubeconfig -f -
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
  name: system:kube-apiserver
  namespace: ""
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:kube-apiserver-to-kubelet
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: User
    name: kubernetes
EOF
```

### Kubernetes 前端负载均衡

在本部分中，您将提供一个外部负载平衡器来管理Kubernetes API服务器。在kubernetes-the-hard-way静态IP地址将被连接到所产生的负载平衡器。

在本教程中创建的计算实例将无权完成本节。从用于创建计算实例的同一台计算机上运行以下命令。

设置网络负载平衡器


忽略

## 09. 引导Kubernetes Worker节点

在本实验中，您将引导三个Kubernetes wroker节点。以下组件将安装在每个节点上：runc，容器网络插件，containerd，kubelet和kube-proxy。

### 下载安装部署

以下命令必须在每个工人实例中运行。  
安装操作系统依赖项,禁用Swap。  
下载二进制文件，创建目录，部署二进制文件。

```
yum -y install socat conntrack ipset
swapon --show
swapoff -a

wget  \
  https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.18.0/crictl-v1.18.0-linux-amd64.tar.gz \
  https://github.com/opencontainers/runc/releases/download/v1.0.0-rc91/runc.amd64 \
  https://github.com/containernetworking/plugins/releases/download/v0.8.6/cni-plugins-linux-amd64-v0.8.6.tgz \
  https://github.com/containerd/containerd/releases/download/v1.3.6/containerd-1.3.6-linux-amd64.tar.gz \
  https://storage.googleapis.com.cnpmjs.org/kubernetes-release/release/v1.18.6/bin/linux/amd64/kubectl \
  https://storage.googleapis.com.cnpmjs.org/kubernetes-release/release/v1.18.6/bin/linux/amd64/kube-proxy \
  https://storage.googleapis.com.cnpmjs.org/kubernetes-release/release/v1.18.6/bin/linux/amd64/kubelet;

sudo mkdir -p \
  /etc/cni/net.d \
  /opt/cni/bin \
  /var/lib/kubelet \
  /var/lib/kube-proxy \
  /var/lib/kubernetes \
  /var/run/kubernetes;

mkdir containerd;
tar -xvf crictl-v1.18.0-linux-amd64.tar.gz;
tar -xvf containerd-1.3.6-linux-amd64.tar.gz -C containerd;
sudo tar -xvf cni-plugins-linux-amd64-v0.8.6.tgz -C /opt/cni/bin/;
sudo mv runc.amd64 runc;
chmod +x crictl kubectl kube-proxy kubelet runc ;
sudo mv crictl kubectl kube-proxy kubelet runc /usr/local/bin/;
sudo mv containerd/bin/* /bin/;
```

> socat二进制文件启用对kubectl port-forward命令的支持。  
> 禁用swap，并禁止开机启动挂载swap

### 配置CNI网络

检索当前计算实例的Pod CIDR范围：


```
POD_CIDR="10.200.0.0/16"
```

- 不同的网络插件配置不通的bridge网络配置文件

创建bridge网络配置文件(==以下配合仅适配containerd==)：

```
cat <<EOF | sudo tee /etc/cni/net.d/10-bridge.conf
{
    "cniVersion": "0.3.1",
    "name": "bridge",
    "type": "bridge",
    "bridge": "cnio0",
    "isGateway": true,
    "ipMasq": true,
    "ipam": {
        "type": "host-local",
        "ranges": [
          [{"subnet": "${POD_CIDR}"}]
        ],
        "routes": [{"dst": "0.0.0.0/0"}]
    }
}
EOF
```

创建loopback网络配置文件：

```
cat <<EOF | sudo tee /etc/cni/net.d/99-loopback.conf
{
    "cniVersion": "0.3.1",
    "name": "lo",
    "type": "loopback"
}
EOF
```

### 配置 containerd

![image](https://note.youdao.com/yws/res/44748/3A6C028520204008BCD5054FBC4D80D9)
```
sudo mkdir -p /etc/containerd/
cat << EOF | sudo tee /etc/containerd/config.toml
[plugins]
  [plugins.cri.containerd]
    snapshotter = "overlayfs"
    [plugins.cri.containerd.default_runtime]
      runtime_type = "io.containerd.runtime.v1.linux"
      runtime_engine = "/usr/local/bin/runc"
      runtime_root = ""
  [plugins.cri]
    sandbox_image = "registry.aliyuncs.com/google_containers/pause:3.2"
EOF
```

创建containerd.service系统单元文件：

```
cat <<EOF | sudo tee /etc/systemd/system/containerd.service
[Unit]
Description=containerd container runtime
Documentation=https://containerd.io
After=network.target

[Service]
ExecStartPre=/sbin/modprobe overlay
ExecStart=/bin/containerd
Restart=always
RestartSec=5
Delegate=yes
KillMode=process
OOMScoreAdjust=-999
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity

[Install]
WantedBy=multi-user.target
EOF
```

### 配置Kubelet use containerd

```
HOSTNAME=$(ifconfig eth0 | grep -oP '(?<=inet )(\d+\.){3}\d+')
sudo mv ${HOSTNAME}-key.pem ${HOSTNAME}.pem /var/lib/kubelet/
sudo mv ${HOSTNAME}.kubeconfig /var/lib/kubelet/kubeconfig
sudo mv ca.pem /var/lib/kubernetes/
POD_CIDR="10.200.0.0/16"
```


创建kubelet-config.yaml配置文件：


```
cat <<EOF | sudo tee /var/lib/kubelet/kubelet-config.yaml
kind: KubeletConfiguration
apiVersion: kubelet.config.k8s.io/v1beta1
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
  x509:
    clientCAFile: "/var/lib/kubernetes/ca.pem"
authorization:
  mode: Webhook
clusterDomain: "cluster.local"
clusterDNS:
  - "10.32.0.10"
podCIDR: "${POD_CIDR}"
resolvConf: "/run/systemd/resolve/resolv.conf"
runtimeRequestTimeout: "15m"
tlsCertFile: "/var/lib/kubelet/${HOSTNAME}.pem"
tlsPrivateKeyFile: "/var/lib/kubelet/${HOSTNAME}-key.pem"
EOF

mkdir /run/systemd/resolve/
cp /etc/resolv.conf /run/systemd/resolve/resolv.conf
```

> 当使用CoreDNS在运行 systemd-resolved 的系统上进行服务发现时，使用 resolvConf 配置来避免循环。

创建kubelet.service系统单元文件：


```
cat <<EOF | sudo tee /etc/systemd/system/kubelet.service
[Unit]
Description=Kubernetes Kubelet
Documentation=https://github.com/kubernetes/kubernetes
After=containerd.service
Requires=containerd.service

[Service]
ExecStart=/usr/local/bin/kubelet \\
  --hostname-override=${HOSTNAME} \\
  --config=/var/lib/kubelet/kubelet-config.yaml \\
  --container-runtime=remote \\
  --container-runtime-endpoint=unix:///var/run/containerd/containerd.sock \\
  --image-pull-progress-deadline=2m \\
  --kubeconfig=/var/lib/kubelet/kubeconfig \\
  --network-plugin=cni \\
  --register-node=true \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

### 配置Kubelet use docker

```
HOSTNAME=$(ifconfig eth0 | grep -oP '(?<=inet )(\d+\.){3}\d+')
sudo mv ${HOSTNAME}-key.pem ${HOSTNAME}.pem /var/lib/kubelet/
sudo mv ${HOSTNAME}.kubeconfig /var/lib/kubelet/kubeconfig
sudo mv ca.pem /var/lib/kubernetes/
POD_CIDR="10.200.0.0/16"
```

安装docker

```
sudo yum install -y yum-utils device-mapper-persistent-data lvm2
sudo yum-config-manager --add-repo https://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo
sudo yum makecache fast
yum install docker-ce-19.03.9-3.el7 -y
systemctl  enable docker
systemctl  start docker
```

创建kubelet-config.yaml配置文件：


``` bash
cat <<EOF | sudo tee /var/lib/kubelet/kubelet-config.yaml
kind: KubeletConfiguration
apiVersion: kubelet.config.k8s.io/v1beta1
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
  x509:
    clientCAFile: "/var/lib/kubernetes/ca.pem"
authorization:
  mode: Webhook
clusterDomain: "cluster.local"
clusterDNS:
  - "10.32.0.10"
podCIDR: "${POD_CIDR}"
resolvConf: "/etc/resolv.conf"
runtimeRequestTimeout: "15m"
tlsCertFile: "/var/lib/kubelet/${HOSTNAME}.pem"
tlsPrivateKeyFile: "/var/lib/kubelet/${HOSTNAME}-key.pem"
kubeletCgroups: /systemd/system.slice
EOF

mkdir /run/systemd/resolve/
cat << EOF | tee /run/systemd/resolve/resolv.conf
options timeout:1 rotate
; generated by /usr/sbin/dhclient-script
nameserver 223.5.5.5
nameserver 223.6.6.6
EOF
```

> 当使用CoreDNS在运行 systemd-resolved 的系统上进行服务发现时，使用 resolvConf 配置来避免循环。

创建kubelet.service系统单元文件：


```
cat <<EOF | sudo tee /etc/systemd/system/kubelet.service
[Unit]
Description=Kubernetes Kubelet Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=docker.service
Wants=docker.socket

[Service]
User=root
EnvironmentFile=-/etc/kubernetes/kubelet.env
ExecStart=/usr/local/bin/kubelet \\
                \$KUBE_LOGTOSTDERR \\
                \$KUBE_LOG_LEVEL \\
                \$KUBELET_API_SERVER \\
                \$KUBELET_ADDRESS \\
                \$KUBELET_PORT \\
                \$KUBELET_HOSTNAME \\
                \$KUBELET_ARGS \\
                \$DOCKER_SOCKET \\
                \$KUBELET_NETWORK_PLUGIN \\
                \$KUBELET_VOLUME_PLUGIN \\
                \$KUBELET_CLOUDPROVIDER
Restart=always
RestartSec=10s

[Install]
WantedBy=multi-user.target
EOF
```

```
cat <<EOF | sudo tee /etc/kubernetes/kubelet.env
KUBE_LOGTOSTDERR="--logtostderr=true"
KUBE_LOG_LEVEL="--v=2"
KUBELET_ADDRESS="--node-ip=${HOSTNAME}"
KUBELET_HOSTNAME="--hostname-override=${HOSTNAME}"

KUBELET_ARGS="--bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf \
--config=/var/lib/kubelet/kubelet-config.yaml \
--kubeconfig=/var/lib/kubelet/kubeconfig \
--pod-infra-container-image=registry.aliyuncs.com/google_containers/pause:3.2 \
--runtime-cgroups=/systemd/system.slice \
   "
KUBELET_NETWORK_PLUGIN="--network-plugin=cni --cni-conf-dir=/etc/cni/net.d --cni-bin-dir=/opt/cni/bin"
KUBELET_CLOUDPROVIDER=""

PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
EOF
```

```
systemctl daemon-reload
systemctl  restart kubelet  
```


### 配置 Kubernetes Proxy

创建配置文件及system unit文件

```
sudo mv kube-proxy.kubeconfig /var/lib/kube-proxy/kubeconfig

cat <<EOF | sudo tee /var/lib/kube-proxy/kube-proxy-config.yaml
kind: KubeProxyConfiguration
apiVersion: kubeproxy.config.k8s.io/v1alpha1
clientConnection:
  kubeconfig: "/var/lib/kube-proxy/kubeconfig"
mode: "iptables"
clusterCIDR: "10.200.0.0/16"
EOF

HOSTNAME=$(ifconfig eth0 | grep -oP '(?<=inet )(\d+\.){3}\d+')
cat <<EOF | sudo tee /etc/systemd/system/kube-proxy.service
[Unit]
Description=Kubernetes Kube Proxy
Documentation=https://github.com/kubernetes/kubernetes

[Service]
ExecStart=/usr/local/bin/kube-proxy \\
  --hostname-override=${HOSTNAME} \\
  --config=/var/lib/kube-proxy/kube-proxy-config.yaml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
```

### 启动工作节点服务

```
systemctl daemon-reload
systemctl enable docker kubelet kube-proxy
systemctl start docker kubelet kube-proxy
```

### 验证

```
kubectl get nodes --kubeconfig admin.kubeconfig
```

## 10. 配置kubectl进行远程访问

在本实验中，您将kubectl基于admin用户凭据为命令行实用程序生成kubeconfig文件。

从用于生成管理客户端证书的同一目录中运行此实验中的命令。

### Admin Kubernetes配置文件

每个kubeconfig都需要连接Kubernetes API服务器。为了支持高可用性，将使用分配给Kubernetes API服务器前面的外部负载均衡器的IP地址。

生成适合作为admin用户身份验证的kubeconfig文件：

```
KUBERNETES_PUBLIC_ADDRESS=$(负载均衡IP)

  kubectl config set-cluster kubernetes-the-hard-way \
    --certificate-authority=ca.pem \
    --embed-certs=true \
    --server=https://${KUBERNETES_PUBLIC_ADDRESS}:6443

  kubectl config set-credentials admin \
    --client-certificate=admin.pem \
    --client-key=admin-key.pem

  kubectl config set-context kubernetes-the-hard-way \
    --cluster=kubernetes-the-hard-way \
    --user=admin

  kubectl config use-context kubernetes-the-hard-way
```

## 11. 设置Pod网络路由

### calico

调度到节点的Pod从该节点的Pod CIDR范围接收IP地址。此时，由于缺少网络路由， Pod无法与在不同节点上运行的其他Pod通信。

在本实验中，您将为每个工作节点创建一条路由，该路由将节点的Pod CIDR范围映射到节点的内部IP地址。

还有[其他方法](https://kubernetes.io/docs/concepts/cluster-administration/networking/#how-to-achieve-this)可以实现Kubernetes网络模型。

使用calico配置pod 路由。

https://docs.projectcalico.org/getting-started/kubernetes/self-managed-onprem/onpremises#install-calico-with-etcd-datastore

![image](https://note.youdao.com/yws/res/44792/EB35B5CA106340E89F55EC36739537D3)

在其中一台Master上执行以下命令

下载配置文件，修改pod CIDR地址。

```
curl https://docs.projectcalico.org/manifests/calico-etcd.yaml -o calico.yaml
sed -i 's/# - name: CALICO_IPV4POOL_CIDR/- name: CALICO_IPV4POOL_CIDR/' calico.yaml   
sed -i 's/#   value: "192.168.0.0/  value: "10.200.0.0/'  calico.yaml  
sed -i 's/defaultMode: 0400/defaultMode: 0777/g' calico.yaml 

calico.yaml 文件中修改etcd endpoint地址，及修改证书地址
  etcd_endpoints: "https://10.0.0.40:2379,https://10.0.0.45:2379,https://10.0.0.48:2379"
  # If you're using TLS enabled etcd uncomment the following.
  # You must also populate the Secret below with these files.
  etcd_ca: "/calico-secrets/etcd-ca"
  etcd_cert: "/calico-secrets/etcd-cert"
  etcd_key: "/calico-secrets/etcd-key"
calico.yaml 文件中修改secret calico-etcd-secrets中的证书
calico.yaml 文件中在ds/calico-node 中添加环境变量（kubelet注册的主机名为IP，这里指定calico节点名为主机IP ）

在CALICO_IPV4POOL_IPIP下新增 CALICO_IPV4POOL_BLOCK_SIZE 与 NODENAME。

            - name: CALICO_IPV4POOL_IPIP
              value: "Always"
            - name: CALICO_IPV4POOL_BLOCK_SIZE
              value: "24"
            - name: NODENAME
              valueFrom:
                fieldRef:
                  fieldPath: status.podIP

kubectl apply -f calico.yaml  
```

![image](https://note.youdao.com/yws/res/44830/D261BB230145418C8918B48EA48D56E5)

查看路由

```
# route -n
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         10.0.0.1        0.0.0.0         UG    0      0        0 eth0
10.0.0.0        0.0.0.0         255.0.0.0       U     0      0        0 eth0
10.200.24.0     0.0.0.0         255.255.255.0   U     0      0        0 docker0
10.200.29.0     10.0.0.45       255.255.255.0   UG    0      0        0 tunl0
10.200.51.0     0.0.0.0         255.255.255.255 UH    0      0        0 calic1f2f68740c
10.200.51.0     0.0.0.0         255.255.255.0   U     0      0        0 *
10.200.51.2     0.0.0.0         255.255.255.255 UH    0      0        0 cali12d4a061371
10.200.92.0     10.0.0.48       255.255.255.0   UG    0      0        0 tunl0
10.200.118.0    10.0.0.48       255.255.255.0   UG    0      0        0 tunl0
10.200.220.0    10.0.0.45       255.255.255.0   UG    0      0        0 tunl0
169.254.0.0     0.0.0.0         255.255.0.0     U     1002   0        0 eth0
```

另：

calico 在etcd中的存储位置： `/calico/resources/v3/projectcalico.org/nodes/10.0.0.48`

```
查询某个前缀的所有key
etcdctl get --prefix --keys-only /calico
etcdctl get --prefix --keys-only /calico/ipam/
查询某个前缀的所有key及其值
etcdctl get --prefix /calico
删除某个前缀的所有key
etcdctl  del --prefix --prev-kv "/calico"

```


参考文档：

1. https://docs.projectcalico.org/getting-started/clis/calicoctl/install
2. https://docs.projectcalico.org/reference/node/configuration#node-name-determination
3. https://docs.projectcalico.org/getting-started/kubernetes/self-managed-onprem/
4. https://docs.projectcalico.org/getting-started/kubernetes/self-managed-onprem/onpremises
5. https://docs.projectcalico.org/getting-started/kubernetes/hardway/
6. https://docs.projectcalico.org/getting-started/kubernetes/hardway/install-cni-plugin

#### Install calicoctl 

```
wget https://github.com/projectcalico/calicoctl/releases/download/v3.17.1/calicoctl
chmod +x calicoctl 
mv calicoctl /bin
calicoctl node status

ETCD_ENDPOINTS=http://127.0.0.1:2379 calicoctl get ippool -o wide
ETCD_ENDPOINTS=http://127.0.0.1:2379 calicoctl get hostEndpoint -o wide


```

### flannel

https://github.com/coreos/flannel/blob/master/Documentation/running.md

仅在其中一台Master上执行

```
POD_CIDR="10.200.0.0/16"
HOSTNAME=$(ifconfig eth0 | grep -oP '(?<=inet )(\d+\.){3}\d+')
ETCDCTL_API=2 etcdctl  --cert-file /etc/etcd/kubernetes.pem --key-file /etc/etcd/kubernetes-key.pem --ca-file /etc/etcd/ca.pem --endpoints https://${HOSTNAME}:2379 set /coreos.com/network/config '{ "Network": "10.200.0.0/16", "Backend": {"Type": "vxlan","Directrouting":false}}'
```

每台主机上执行

```
wget https://github.com/coreos/flannel/releases/download/v0.13.0/flanneld-amd64
chmod +x flanneld-amd64
mv flanneld-amd64 /bin/flanneld
```

```
mkdir /etc/flannel/
HOSTNAME=$(ifconfig eth0 | grep -oP '(?<=inet )(\d+\.){3}\d+')
ETCD_CLUSTER="https://10.0.0.40:2379,https://10.0.0.45:2379,https://10.0.0.48:2379"

cat << EOF | tee /etc/flannel/flannel.env
FLANNEL_ETCD="--etcd-endpoints=${ETCD_CLUSTER}"
FLANNEL_ETCD_KEY="--etcd-prefix=/coreos.com/network"
FLANNEL_ETCD_CAFILE="--etcd-cafile=/etc/etcd/ca.pem"
FLANNEL_ETCD_CERTFILE="--etcd-certfile=/etc/etcd/kubernetes.pem"
FLANNEL_ETCD_KEYFILE="--etcd-keyfile=/etc/etcd/kubernetes-key.pem"
FLANNEL_IFACE="--iface=eth0"
FLANNEL_PUBLIC_IP="--public-ip=${HOSTNAME}"
EOF

cat << EOF | tee /usr/lib/systemd/system/flanneld.service
[Unit]
Description=Flanneld overlay address etcd agent
After=network.target
Before=docker.service

[Service]
EnvironmentFile=-/etc/flannel/flannel.env
# ExecStartPre=/opt/kubernetes/bin/remove-docker0.sh
ExecStart=/bin/flanneld \${FLANNEL_IFACE} \${FLANNEL_PUBLIC_IP} \${FLANNEL_ETCD} \${FLANNEL_ETCD_KEY} \${FLANNEL_ETCD_CAFILE} \${FLANNEL_ETCD_CERTFILE} \${FLANNEL_ETCD_KEYFILE}
# ExecStartPost=/opt/kubernetes/bin/mk-docker-opts.sh -d /run/flannel/docker

Type=notify

[Install]
WantedBy=multi-user.target
RequiredBy=docker.service
EOF

source /run/flannel/subnet.env
cat << EOF | tee /etc/docker/daemon.json
{
"bip": "${FLANNEL_SUBNET}",
"ip-masq": true,
"mtu": 1450
}
EOF
```

创建bridge网络配置文件：

```
cat <<EOF | sudo tee /etc/cni/net.d/10-bridge.conf
{
        "cniVersion":"0.3.1",
        "name": "flannel",
        "type": "flannel",
        "delegate": {
            "bridge": "docker0",
            "isDefaultGateway": true,
            "mtu": 1400
        }
}
EOF
```

```
systemctl  daemon-reload
systemctl  start flanneld
systemctl  start docker
```

flannel从租约中删除TTL，将其转换为预订。

选择一台Master，执行以下命令

```
HOSTNAME=$(ifconfig eth0 | grep -oP '(?<=inet )(\d+\.){3}\d+')

for i in $(ETCDCTL_API=2 etcdctl  --cert-file /etc/etcd/kubernetes.pem --key-file /etc/etcd/kubernetes-key.pem --ca-file /etc/etcd/ca.pem --endpoints https://${HOSTNAME}:2379 ls /coreos.com/network/subnets/);do

ETCDCTL_API=2 etcdctl  --cert-file /etc/etcd/kubernetes.pem --key-file /etc/etcd/kubernetes-key.pem --ca-file /etc/etcd/ca.pem --endpoints https://${HOSTNAME}:2379 set -ttl 0 $i $(ETCDCTL_API=2 etcdctl  --cert-file /etc/etcd/kubernetes.pem --key-file /etc/etcd/kubernetes-key.pem --ca-file /etc/etcd/ca.pem --endpoints https://${HOSTNAME}:2379 get $i);

ETCDCTL_API=2 etcdctl  --cert-file /etc/etcd/kubernetes.pem --key-file /etc/etcd/kubernetes-key.pem --ca-file /etc/etcd/ca.pem --endpoints https://${HOSTNAME}:2379 -o extended   ls $i

done
```

测试

```
kubectl create deploy nginx --image=nginx
kubectl scale --replicas=5 deploy/nginx
```



## 12. 部署DNS群集附加组件

在Kubernetes集群中运行的应用程序提供由CoreDNS支持的基于DNS的服务发现。

### DNS群集附件

```
kubectl apply -f https://storage.googleapis.com/kubernetes-the-hard-way/coredns-1.7.0.yaml

kubectl get pods -l k8s-app=kube-dns -n kube-system

```


### 验证

```
kubectl run busybox --image=busybox:1.28 --command -- sleep 3600

kubectl get pods -l run=busybox

POD_NAME=$(kubectl get pods -l run=busybox -o jsonpath="{.items[0].metadata.name}")

kubectl exec -ti $POD_NAME -- nslookup kubernetes

```

```
kubectl create deploy nginx --image=nginx

kubectl expose deploy nginx --port=80 --target-port=80  

POD_NAME=$(kubectl get pods -l run=busybox -o jsonpath="{.items[0].metadata.name}")

kubectl exec -ti $POD_NAME -- nslookup nginx

```


