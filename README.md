
```
cd flask_chat
docker buildx build --platform linux/amd64 -t equalitie/baskerville_ai:base2 .
docker push equalitie/baskerville_ai:base2

docker buildx build --no-cache --platform  linux/amd64 -t equalitie/baskerville_ai:latest -f Dockerfile_latest .
docker push equalitie/baskerville_ai:latest
```

```commandline
kubectl apply -f secret.yaml
kubectl apply -f config.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
```

```commandline
kubectl port-forward service/baskerville-ai-service 8080:80
```

```commandline

helm repo add nvidia https://helm.ngc.nvidia.com/nvidia
helm repo update
 --version 23.9.2 \
 
helm upgrade --install gpu-operator nvidia/gpu-operator \
  -n gpu-operator \
  --create-namespace \
  -f gpu-values.yaml \
  --set operator.defaultRuntime=containerd


```