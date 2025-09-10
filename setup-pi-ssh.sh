#!/bin/bash

# Setup script to enable password authentication on Pi via SD card
# Run this when Pi SD card is mounted

set -e

echo "🔧 Setting up Pi SSH configuration..."

# Check if we can reach the Pi
PI_IP="192.168.4.71"
if ! ping -c 2 "$PI_IP" >/dev/null 2>&1; then
    echo "❌ Cannot reach Pi at $PI_IP"
    echo "Make sure Pi is booted and connected to network"
    exit 1
fi

echo "✅ Pi is reachable"

# Create a script to enable password auth and setup SSH key
cat > setup_ssh.sh <<'EOF'
#!/bin/bash
echo "🔧 Setting up SSH on Pi..."

# Enable password authentication
sudo sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Also allow pubkey auth
sudo sed -i 's/#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config

# Restart SSH service
sudo systemctl restart ssh

# Setup SSH key for raspberrypi user
mkdir -p ~/.ssh
chmod 700 ~/.ssh

# Add the public key
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINDAL0xw5HQ8OQIpwPv9jRZnZDrcVJs57HFQ9nJKIx1u vandanchopra@Vandans-MacBook-Pro-2.local" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

echo "✅ SSH setup complete"
EOF

# Try to copy and run the setup script on Pi
echo "📤 Uploading SSH setup script..."

# Use expect to handle password prompt
expect << 'EXPECT_EOF'
set timeout 30
spawn scp setup_ssh.sh raspberrypi@192.168.4.71:/home/raspberrypi/
expect {
    "password:" {
        send "pi\r"
        expect eof
    }
    "Permission denied" {
        puts "❌ SSH connection failed"
        exit 1
    }
    timeout {
        puts "❌ Connection timeout"
        exit 1
    }
}
EXPECT_EOF

if [ $? -eq 0 ]; then
    echo "✅ Script uploaded successfully"
    
    # Run the setup script
    echo "🔧 Running SSH setup on Pi..."
    expect << 'EXPECT_EOF2'
    set timeout 60
    spawn ssh raspberrypi@192.168.4.71 "chmod +x setup_ssh.sh && ./setup_ssh.sh"
    expect {
        "password:" {
            send "pi\r"
            expect eof
        }
        "Permission denied" {
            puts "❌ SSH execution failed"
            exit 1
        }
        timeout {
            puts "❌ Execution timeout"
            exit 1
        }
    }
EXPECT_EOF2
    
    if [ $? -eq 0 ]; then
        echo "✅ SSH setup completed on Pi"
        echo "🔑 Testing new SSH connection..."
        
        # Test the connection
        ssh -o PasswordAuthentication=no raspberrypi@192.168.4.71 "echo 'SSH key auth working!'"
        
        if [ $? -eq 0 ]; then
            echo "🎉 SSH key authentication is now working!"
        else
            echo "⚠️  SSH key auth not working, but password should now work"
        fi
    else
        echo "❌ Failed to run setup script on Pi"
    fi
else
    echo "❌ Failed to upload script to Pi"
fi

# Cleanup
rm -f setup_ssh.sh

echo "🏁 SSH setup process complete"