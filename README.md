# ca_cert_blacklist
Shell script to block, and later restore, compromised root CA certificates on Fedora-based systems.

Usage guidelines:
curl -O https://raw.githubusercontent.com/zero-copy-jim/ca_cert_blacklist/main/block-cert.sh
chmod +x block-cert.sh

./block-cert.sh --check            # report only, no root needed
sudo ./block-cert.sh               # block both roots, then verify
sudo BLOCK_AAA=0 ./block-cert.sh   # block only the emSign root
sudo ./block-cert.sh --undo        # remove the blocklist entries
