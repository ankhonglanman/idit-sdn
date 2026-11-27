<?xml version="1.0" encoding="UTF-8"?>
<simconf>
  <project EXPORT="discard">[APPS_DIR]/mrm</project>
  <project EXPORT="discard">[APPS_DIR]/mspsim</project>
  <project EXPORT="discard">[APPS_DIR]/avrora</project>
  <project EXPORT="discard">[APPS_DIR]/serial_socket</project>
  <project EXPORT="discard">[APPS_DIR]/collect-view</project>
  <project EXPORT="discard">[APPS_DIR]/powertracker</project>
  <simulation>
    <title>IDIT-SDN Energy + TRANS_TS Validation (3x3 Z1 Grid)</title>
    <randomseed>123456</randomseed>
    <motedelay_us>1000000</motedelay_us>
    <radiomedium>
      org.contikios.cooja.radiomediums.UDGM
      <transmitting_range>45.0</transmitting_range>
      <interference_range>45.0</interference_range>
      <success_ratio_tx>1.0</success_ratio_tx>
      <success_ratio_rx>1.0</success_ratio_rx>
    </radiomedium>
    <events>
      <logoutput>40000</logoutput>
    </events>
    <motetype>
      org.contikios.cooja.mspmote.Z1MoteType
      <identifier>z1_ctrl</identifier>
      <description>controller</description>
      <firmware EXPORT="copy">[CONFIG_DIR]/../applications/attack-energy/controller-node.z1</firmware>
      <moteinterface>org.contikios.cooja.interfaces.Position</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.RimeAddress</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.IPAddress</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.Mote2MoteRelations</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.MoteAttributes</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspClock</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspMoteID</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspButton</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.Msp802154Radio</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspDefaultSerial</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspLED</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspDebugOutput</moteinterface>
    </motetype>
    <motetype>
      org.contikios.cooja.mspmote.Z1MoteType
      <identifier>z1_sink</identifier>
      <description>sink</description>
      <firmware EXPORT="copy">[CONFIG_DIR]/../applications/attack-energy/sink-node.z1</firmware>
      <moteinterface>org.contikios.cooja.interfaces.Position</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.RimeAddress</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.IPAddress</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.Mote2MoteRelations</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.MoteAttributes</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspClock</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspMoteID</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspButton</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.Msp802154Radio</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspDefaultSerial</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspLED</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspDebugOutput</moteinterface>
    </motetype>
    <motetype>
      org.contikios.cooja.mspmote.Z1MoteType
      <identifier>z1_node</identifier>
      <description>enabled</description>
      <firmware EXPORT="copy">[CONFIG_DIR]/../applications/attack-energy/enabled-node.z1</firmware>
      <moteinterface>org.contikios.cooja.interfaces.Position</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.RimeAddress</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.IPAddress</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.Mote2MoteRelations</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.MoteAttributes</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspClock</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspMoteID</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspButton</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.Msp802154Radio</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspDefaultSerial</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspLED</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspDebugOutput</moteinterface>
    </motetype>
    <motetype>
      org.contikios.cooja.mspmote.Z1MoteType
      <identifier>z1_att</identifier>
      <description>attacker fdff</description>
      <firmware EXPORT="copy">[CONFIG_DIR]/../applications/attack-energy/attack-fdff.z1</firmware>
      <moteinterface>org.contikios.cooja.interfaces.Position</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.RimeAddress</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.IPAddress</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.Mote2MoteRelations</moteinterface>
      <moteinterface>org.contikios.cooja.interfaces.MoteAttributes</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspClock</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspMoteID</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspButton</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.Msp802154Radio</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspDefaultSerial</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspLED</moteinterface>
      <moteinterface>org.contikios.cooja.mspmote.interfaces.MspDebugOutput</moteinterface>
    </motetype>
    <mote><breakpoints /><interface_config>org.contikios.cooja.interfaces.Position<x>0.0</x><y>0.0</y><z>0.0</z></interface_config><interface_config>org.contikios.cooja.mspmote.interfaces.MspClock<deviation>1.0</deviation></interface_config><interface_config>org.contikios.cooja.mspmote.interfaces.MspMoteID<id>1</id></interface_config><motetype_identifier>z1_ctrl</motetype_identifier></mote>
    <mote><breakpoints /><interface_config>org.contikios.cooja.interfaces.Position<x>35.0</x><y>0.0</y><z>0.0</z></interface_config><interface_config>org.contikios.cooja.mspmote.interfaces.MspClock<deviation>1.0</deviation></interface_config><interface_config>org.contikios.cooja.mspmote.interfaces.MspMoteID<id>2</id></interface_config><motetype_identifier>z1_node</motetype_identifier></mote>
    <mote><breakpoints /><interface_config>org.contikios.cooja.interfaces.Position<x>70.0</x><y>0.0</y><z>0.0</z></interface_config><interface_config>org.contikios.cooja.mspmote.interfaces.MspClock<deviation>1.0</deviation></interface_config><interface_config>org.contikios.cooja.mspmote.interfaces.MspMoteID<id>3</id></interface_config><motetype_identifier>z1_sink</motetype_identifier></mote>
    <mote><breakpoints /><interface_config>org.contikios.cooja.interfaces.Position<x>0.0</x><y>35.0</y><z>0.0</z></interface_config><interface_config>org.contikios.cooja.mspmote.interfaces.MspClock<deviation>1.0</deviation></interface_config><interface_config>org.contikios.cooja.mspmote.interfaces.MspMoteID<id>4</id></interface_config><motetype_identifier>z1_node</motetype_identifier></mote>
    <mote><breakpoints /><interface_config>org.contikios.cooja.interfaces.Position<x>35.0</x><y>35.0</y><z>0.0</z></interface_config><interface_config>org.contikios.cooja.mspmote.interfaces.MspClock<deviation>1.0</deviation></interface_config><interface_config>org.contikios.cooja.mspmote.interfaces.MspMoteID<id>5</id></interface_config><motetype_identifier>z1_att</motetype_identifier></mote>
    <mote><breakpoints /><interface_config>org.contikios.cooja.interfaces.Position<x>70.0</x><y>35.0</y><z>0.0</z></interface_config><interface_config>org.contikios.cooja.mspmote.interfaces.MspClock<deviation>1.0</deviation></interface_config><interface_config>org.contikios.cooja.mspmote.interfaces.MspMoteID<id>6</id></interface_config><motetype_identifier>z1_node</motetype_identifier></mote>
    <mote><breakpoints /><interface_config>org.contikios.cooja.interfaces.Position<x>0.0</x><y>70.0</y><z>0.0</z></interface_config><interface_config>org.contikios.cooja.mspmote.interfaces.MspClock<deviation>1.0</deviation></interface_config><interface_config>org.contikios.cooja.mspmote.interfaces.MspMoteID<id>7</id></interface_config><motetype_identifier>z1_node</motetype_identifier></mote>
    <mote><breakpoints /><interface_config>org.contikios.cooja.interfaces.Position<x>35.0</x><y>70.0</y><z>0.0</z></interface_config><interface_config>org.contikios.cooja.mspmote.interfaces.MspClock<deviation>1.0</deviation></interface_config><interface_config>org.contikios.cooja.mspmote.interfaces.MspMoteID<id>8</id></interface_config><motetype_identifier>z1_node</motetype_identifier></mote>
    <mote><breakpoints /><interface_config>org.contikios.cooja.interfaces.Position<x>70.0</x><y>70.0</y><z>0.0</z></interface_config><interface_config>org.contikios.cooja.mspmote.interfaces.MspClock<deviation>1.0</deviation></interface_config><interface_config>org.contikios.cooja.mspmote.interfaces.MspMoteID<id>9</id></interface_config><motetype_identifier>z1_node</motetype_identifier></mote>
  </simulation>
  <plugin>org.contikios.cooja.plugins.SimControl<width>280</width><z>0</z><height>160</height><location_x>400</location_x><location_y>0</location_y></plugin>
  <plugin>
    org.contikios.cooja.plugins.ScriptRunner
    <plugin_config>
      <script>sim.setSpeedLimit(null);
TIMEOUT(1800000);
FileWriter = Java.type("java.io.FileWriter");
my_output = new FileWriter("/root/idit-sdn/simulation/results/attack_energy_motes.txt");
while (true) {
    my_output.write(time + ":" + id + ":" + msg + "\n");
    try {
        YIELD();
    } catch (e) {
        my_output.write("Simulation finished.\n");
        my_output.close();
        throw('test script killed');
    }
}</script>
      <active>true</active>
    </plugin_config>
    <width>600</width><z>-1</z><height>700</height><location_x>552</location_x><location_y>64</location_y><minimized>true</minimized>
  </plugin>
  <plugin>
    org.contikios.cooja.serialsocket.SerialSocketServer
    <mote_arg>0</mote_arg>
    <plugin_config><port>60013</port><bound>true</bound></plugin_config>
    <width>362</width><z>1</z><height>116</height><location_x>63</location_x><location_y>399</location_y>
  </plugin>
</simconf>
