# fork instructions

## staging

```bash
git checkout staging
git reset --hard fork
git merge --squash <feature branch>
git checkout fork
git rebase staging
# then publish
```

## publishing

```bash
npm version 0.0.55-foxfirecodes.<next>
npm publish --tag foxfire
```
