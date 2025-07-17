!/bin/bash

YOUR_OBFU_PHRASE="ObfuGuard"

BRANCH=v6.14-bg
REPO_URL="https://github.com/baz2142/obfuguard.git"

REPO_DIR_NAME=obfuguard
DRIVER_DIR=drivers/net/wireguard

#systemctl stop wg-quick@wg0

if [ -d "$REPO_DIR_NAME" ]; then
  echo "The dir '$REPO_DIR_NAME' is found. Updating the sources..."

  cd "$REPO_DIR_NAME"
  git fetch --depth=1 origin "$BRANCH"
  git reset --hard "origin/$BRANCH"
else
  echo "The dir '$REPO_DIR_NAME' is not found. Cloning the repo..."

  git clone --depth=1 --filter=blob:none --sparse --branch "$BRANCH" "$REPO_URL" "$REPO_DIR_NAME"

  cd "$REPO_DIR_NAME"
  git sparse-checkout set $DRIVER_DIR
fi

cd ..

make -C /lib/modules/$(uname -r)/build M=$(pwd)/$REPO_DIR_NAME/$DRIVER_DIR clean
make -C /lib/modules/$(uname -r)/build M=$(pwd)/$REPO_DIR_NAME/$DRIVER_DIR EXTRA_CFLAGS="-DCONFIG_WIREGUARD_DEBUG -DDEBUG" modules

rmmod wireguard | echo "The module wasn't loadeded..."
insmod $(pwd)/$REPO_DIR_NAME/$DRIVER_DIR/wireguard.ko phrase="$YOUR_OBFU_PHRASE"
modinfo $(pwd)/$REPO_DIR_NAME/$DRIVER_DIR/wireguard.ko

#systemctl start wg-quick@wg0