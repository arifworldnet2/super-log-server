# ==========================================================
# MikroTik RouterOS Script for Xtream Log Server Integration
# ==========================================================
# Replace 192.168.1.100 with the actual IP address of your Xtream Log Server host.
# Default Syslog UDP port is 5514 (or 514 if run as administrator).

:local ServerIP "192.168.1.100"
:local ServerPort "5514"

# 1. Configure Remote Logging Action
/system logging action
add name="xtreamlog" target=remote remote=$ServerIP remote-port=$ServerPort bsd-syslog=yes syslog-facility=daemon syslog-severity=auto

# 2. Add System Logging Topics
/system logging
add action=xtreamlog topics=firewall,info
add action=xtreamlog topics=pppoe,info
add action=xtreamlog topics=account,info
add action=xtreamlog topics=system,info

# 3. Enable Logging on NAT Rules (srcnat / masquerade)
# Ensure your src-nat or masquerade rule logs with prefix 'nat:'
# Example:
# /ip firewall nat set [find action=masquerade] log=yes log-prefix="nat:"
# /ip firewall nat set [find action=src-nat] log=yes log-prefix="nat:"

:put "Xtream Log Server MikroTik configuration completed successfully!"
