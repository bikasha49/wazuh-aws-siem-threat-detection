````<ossec_config>
  <client>
    <server>
      <address>WAZUH_MANAGER_PUBLIC_IP</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <crypto_method>aes</crypto_method>
    <notify_time>20</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <enrollment>
      <enabled>yes</enabled>
      <agent_name>Windows2022</agent_name>
    </enrollment>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
    <skip_nfs>yes</skip_nfs>
  </sca>

  <syscheck>
    <disabled>no</disabled>
    <frequency>3600</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>
    <directories check_all="yes" report_changes="yes" realtime="yes" whodata="yes">C:\Users\*\Desktop</directories>
    <directories check_all="yes" report_changes="yes" realtime="yes">C:\WazuhDemo</directories>
    <directories check_all="yes" realtime="yes">C:\Users\*\Downloads</directories>
    <directories check_all="yes" realtime="yes">C:\Users\*\Documents</directories>
    <directories check_all="yes">C:\Windows\System32\drivers\etc</directories>
    <ignore>C:\Windows\System32\LogFiles</ignore>
  </syscheck>

  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="yes">yes</ports>
    <processes>yes</processes>
  </wodle>

  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
    <query>Event/System[EventID != 5145 and EventID != 5156 and EventID != 5447 and EventID != 4656]</query>
  </localfile>

  <localfile>
    <location>System</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>Application</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <logging>
    <log_format>plain</log_format>
  </logging>
</ossec_config>
