#!/bin/bash
set -e

# Setup the integration branch correctly: "Create a branch integration/port from main."
git checkout main
git reset --hard origin/main
git branch -D integration/port || true
git checkout -b integration/port

BRANCHES="origin/jules-12048071818776096492-ddc89a1d origin/jules-18062705680186636212-692905fa origin/jules-4649944338155401763-8f07cc72 origin/jules-7731165589526309209-6cbefb82 origin/jules-port-geo-9479515892024644689-1936166115411947650 origin/port-app-ui-5210074829645659557 origin/port-ci-16545357940856379833 origin/port-enforcer-14850058134630504011 origin/rat-monitor-linux-5610985193425265706 origin/research-interception-12585712235258087719"

for branch in $BRANCHES; do
    echo "====================================="
    echo "Merging $branch"
    if ! git merge -q --allow-unrelated-histories --no-edit $branch; then
        echo "Resolving conflicts..."
        # If there are conflicts outside `port/`, we want to keep `origin/main`'s version. Since we started from main, `git checkout --ours` gets us main's version.
        # But wait, what if `port/` files have conflicts? The instructions say: "Resolve conflicts only in shared glue (port/Cargo.toml, dependency versions); never rewrite a lane's own logic."

        # We will handle conflicts in specific files.
        for file in $(git diff --name-only --diff-filter=U); do
            if [[ "$file" == "port/Cargo.toml" ]]; then
                echo "Recreating port/Cargo.toml"
                cat << 'INNER_EOF' > port/Cargo.toml
[workspace]
resolver = "2"
members = ["crates/*"]
exclude = ["app", "crates/rat-core/fuzz", "crates/rat-daemon/fuzz", "crates/rat-enforcer/fuzz", "crates/rat-geo/fuzz", "crates/rat-names/fuzz", "crates/rat-monitor-linux/fuzz", "crates/rat-monitor-windows/fuzz"]
INNER_EOF
                git add port/Cargo.toml
            elif [[ "$file" == "port/Cargo.lock" ]]; then
                echo "Using --ours for Cargo.lock"
                git checkout --ours port/Cargo.lock
                git add port/Cargo.lock
            elif [[ "$file" == "port/.gitignore" ]]; then
                echo "Recreating port/.gitignore"
                cat << 'INNER_EOF' > port/.gitignore
/target
INNER_EOF
                git add port/.gitignore
            elif [[ "$file" == ".gitignore" ]]; then
                echo "Resolving global .gitignore"
                git checkout --ours .gitignore
                # Ensure node_modules and target are ignored
                grep -q "port/target/" .gitignore || echo "port/target/" >> .gitignore
                grep -q "port/app/node_modules/" .gitignore || echo "port/app/node_modules/" >> .gitignore
                git add .gitignore
            elif [[ "$file" == port/* ]]; then
                echo "Resolving port file conflict with --theirs: $file"
                git checkout --theirs "$file"
                git add "$file"
            else
                echo "Resolving external file conflict with --ours: $file"
                git checkout --ours "$file"
                git add "$file"
            fi
        done

        git commit -q --no-edit
    fi
done

echo "Adding remaining gitignores just in case"
echo "port/target/" >> .gitignore
echo "port/app/node_modules/" >> .gitignore
git add .gitignore
git commit -m "Update gitignore for integration branch" || true
