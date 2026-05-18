#Requires -Version 5.1
# ============================================================
#  Palo Alto Firewall Manager – WPF GUI
#  Requires:  pan-power module  (Install-Module 'pan-power' -Scope CurrentUser)
#  Run with:  PowerShell.exe -STA -File PANManager.ps1
#
#  Based on the script by Steve Borba:
#    https://github.com/sjborbajr/PaloAltoNetworks/blob/main/Install-Software.ps1
#  Credit and thanks to Steve Borba for the original pan-power-driven
#  Install-Software workflow that this GUI extends.
#
#  This is the proven-working sequential single-runspace architecture
#  (one runspace per operation, foreach inside) with a WPF GUI layered on
#  top and an additional Licenses tab that pivots license data into a
#  per-firewall matrix (WildFire / DNS / URL / IoT / Threat / Support).
# ============================================================
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Windows.Forms

# ── Verify pan-power is available ───────────────────────────
if (-not (Get-Module -ListAvailable -Name 'pan-power')) {
    [System.Windows.MessageBox]::Show(
        "The 'pan-power' module is not installed.`n`nInstall it with:`n    Install-Module 'pan-power' -Scope CurrentUser",
        "Missing Module", "OK", "Error") | Out-Null
    exit 1
}
Import-Module pan-power -ErrorAction SilentlyContinue

# ── Observable FirewallDevice model (C#) ────────────────────
Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
public class FirewallDevice : INotifyPropertyChanged {
    public event PropertyChangedEventHandler PropertyChanged;
    private void N(string p) { var h = PropertyChanged; if (h != null) h(this, new PropertyChangedEventArgs(p)); }
    private bool   _sel;   public bool   Selected       { get { return _sel;   } set { _sel   = value; N("Selected");       } }
    private string _hn =""; public string Hostname       { get { return _hn;   } set { _hn    = value; N("Hostname");       } }
    private string _md =""; public string Model          { get { return _md;   } set { _md    = value; N("Model");          } }
    private string _sr =""; public string Serial         { get { return _sr;   } set { _sr    = value; N("Serial");         } }
    private string _ip =""; public string IPAddress      { get { return _ip;   } set { _ip    = value; N("IPAddress");      } }
    private string _sv =""; public string SwVersion      { get { return _sv;   } set { _sv    = value; N("SwVersion");      } }
    private string _hs =""; public string HAState        { get { return _hs;   } set { _hs    = value; N("HAState");        } }
    private string _ht =""; public string HAType         { get { return _ht;   } set { _ht    = value; N("HAType");         } }
    private string _sy =""; public string HASync         { get { return _sy;   } set { _sy    = value; N("HASync");         } }
    private string _hp =""; public string HAPriority     { get { return _hp;   } set { _hp    = value; N("HAPriority");     } }
    private string _hpre="";public string HAPreemptive   { get { return _hpre; } set { _hpre  = value; N("HAPreemptive");   } }
    private string _ps ="—"; public string PingStatus    { get { return _ps;   } set { _ps    = value; N("PingStatus");     } }
    private string _pl ="—"; public string PingLatency   { get { return _pl;   } set { _pl    = value; N("PingLatency");    } }
    private string _dl ="—"; public string DownloadStatus{ get { return _dl;   } set { _dl    = value; N("DownloadStatus"); } }
    private string _in ="—"; public string InstallStatus { get { return _in;   } set { _in    = value; N("InstallStatus");  } }
    private bool  _itv=true; public bool   IsTargetVer   { get { return _itv;  } set { _itv   = value; N("IsTargetVer");    } }
    private string _dj =""; public string DownloadJobId  { get { return _dj;   } set { _dj    = value; N("DownloadJobId");  } }
    private string _ij =""; public string InstallJobId   { get { return _ij;   } set { _ij    = value; N("InstallJobId");   } }
    private string _lwf  ="—"; public string LicWildFire { get { return _lwf;  } set { _lwf  = value; N("LicWildFire"); } }
    private string _ldns ="—"; public string LicDNS      { get { return _ldns; } set { _ldns = value; N("LicDNS");      } }
    private string _lurl ="—"; public string LicURL      { get { return _lurl; } set { _lurl = value; N("LicURL");      } }
    private string _liot ="—"; public string LicIoT      { get { return _liot; } set { _liot = value; N("LicIoT");      } }
    private string _ltp  ="—"; public string LicThreat   { get { return _ltp;  } set { _ltp  = value; N("LicThreat");   } }
    private string _lsup ="—"; public string LicSupport  { get { return _lsup; } set { _lsup = value; N("LicSupport");  } }
    private bool   _lh   =false; public bool LicHasAny       { get { return _lh;   } set { _lh   = value; N("LicHasAny");   } }
}
public class EDLEntry : INotifyPropertyChanged {
    public event PropertyChangedEventHandler PropertyChanged;
    private void N(string p) { var h = PropertyChanged; if (h != null) h(this, new PropertyChangedEventArgs(p)); }
    private bool   _sel;     public bool   Selected    { get { return _sel;  } set { _sel  = value; N("Selected");    } }
    private string _n  =""; public string Name        { get { return _n;    } set { _n    = value; N("Name");        } }
    private string _t  =""; public string Type        { get { return _t;    } set { _t    = value; N("Type");        } }
    private string _u  =""; public string Url         { get { return _u;    } set { _u    = value; N("Url");         } }
    private string _d  =""; public string Description { get { return _d;    } set { _d    = value; N("Description"); } }
}
"@ -ErrorAction SilentlyContinue

# ── XAML ────────────────────────────────────────────────────
[xml]$XAML = @'
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="Palo Alto Firewall Manager"
    Height="940" Width="1500" MinWidth="1100" MinHeight="600"
    Background="#12121E" WindowStartupLocation="CenterScreen"
    FontFamily="Segoe UI" FontSize="12">
  <Window.Resources>
    <Style x:Key="Btn" TargetType="Button">
      <Setter Property="Background" Value="#3949AB"/>
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="Padding"    Value="12,5"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Cursor"     Value="Hand"/>
      <Setter Property="Margin"     Value="3,0"/>
      <Setter Property="FontSize"   Value="11"/>
      <Setter Property="SnapsToDevicePixels" Value="True"/>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#5C6BC0"/></Trigger>
        <Trigger Property="IsEnabled" Value="False"><Setter Property="Background" Value="#2A2A3A"/><Setter Property="Foreground" Value="#555"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="BtnRed" TargetType="Button" BasedOn="{StaticResource Btn}">
      <Setter Property="Background" Value="#C62828"/>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#EF5350"/></Trigger>
        <Trigger Property="IsEnabled" Value="False"><Setter Property="Background" Value="#2A2A3A"/><Setter Property="Foreground" Value="#555"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="BtnGreen" TargetType="Button" BasedOn="{StaticResource Btn}">
      <Setter Property="Background" Value="#1B5E20"/>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#388E3C"/></Trigger>
        <Trigger Property="IsEnabled" Value="False"><Setter Property="Background" Value="#2A2A3A"/><Setter Property="Foreground" Value="#555"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="BtnAmber" TargetType="Button" BasedOn="{StaticResource Btn}">
      <Setter Property="Background" Value="#E65100"/>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#FF7043"/></Trigger>
        <Trigger Property="IsEnabled" Value="False"><Setter Property="Background" Value="#2A2A3A"/><Setter Property="Foreground" Value="#555"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="BtnGray" TargetType="Button" BasedOn="{StaticResource Btn}">
      <Setter Property="Background" Value="#37474F"/>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#546E7A"/></Trigger>
        <Trigger Property="IsEnabled" Value="False"><Setter Property="Background" Value="#2A2A3A"/><Setter Property="Foreground" Value="#555"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="TBox" TargetType="TextBox">
      <Setter Property="Background"  Value="#1E1E30"/>
      <Setter Property="Foreground"  Value="#E0E0F0"/>
      <Setter Property="BorderBrush" Value="#3A3A5C"/>
      <Setter Property="CaretBrush"  Value="White"/>
      <Setter Property="Padding"     Value="6,3"/>
      <Setter Property="FontSize"    Value="12"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
    </Style>
    <Style x:Key="Lbl" TargetType="Label">
      <Setter Property="Foreground" Value="#9090B0"/>
      <Setter Property="FontSize"   Value="11"/>
      <Setter Property="Padding"    Value="0,0,6,0"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
    </Style>
    <Style x:Key="FCB" TargetType="CheckBox">
      <Setter Property="Foreground" Value="#BBBBDD"/>
      <Setter Property="Margin"     Value="5,0"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
      <Setter Property="FontSize"   Value="11"/>
    </Style>
    <Style TargetType="DataGrid">
      <Setter Property="Background"               Value="#1A1A2C"/>
      <Setter Property="Foreground"               Value="#D0D0E8"/>
      <Setter Property="BorderThickness"          Value="0"/>
      <Setter Property="RowBackground"            Value="#1A1A2C"/>
      <Setter Property="AlternatingRowBackground" Value="#1F1F30"/>
      <Setter Property="HorizontalGridLinesBrush" Value="#2A2A40"/>
      <Setter Property="VerticalGridLinesBrush"   Value="#2A2A40"/>
      <Setter Property="RowHeight"                Value="26"/>
      <Setter Property="ColumnHeaderHeight"       Value="30"/>
      <Setter Property="SelectionMode"            Value="Extended"/>
    </Style>
    <Style TargetType="DataGridColumnHeader">
      <Setter Property="Background" Value="#0F0F1E"/>
      <Setter Property="Foreground" Value="#8888AA"/>
      <Setter Property="Padding"    Value="8,0"/>
      <Setter Property="BorderBrush"     Value="#2A2A40"/>
      <Setter Property="BorderThickness" Value="0,0,1,1"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="FontSize"   Value="11"/>
    </Style>
    <Style x:Key="GridRow" TargetType="DataGridRow">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Foreground"  Value="#D0D0E8"/>
      <Style.Triggers>
        <DataTrigger Binding="{Binding HAState}" Value="active"><Setter Property="Background" Value="#0D2010"/></DataTrigger>
        <DataTrigger Binding="{Binding HAState}" Value="passive"><Setter Property="Background" Value="#201800"/></DataTrigger>
        <DataTrigger Binding="{Binding IsTargetVer}" Value="False"><Setter Property="Foreground" Value="#FF7043"/></DataTrigger>
        <DataTrigger Binding="{Binding Selected}" Value="True"><Setter Property="FontWeight" Value="SemiBold"/></DataTrigger>
        <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#252540"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style TargetType="TabControl">
      <Setter Property="Background"      Value="#1A1A2C"/>
      <Setter Property="BorderBrush"     Value="#2A2A40"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding"         Value="0"/>
    </Style>
    <Style TargetType="TabItem">
      <Setter Property="Background"      Value="#0F0F1E"/>
      <Setter Property="Foreground"      Value="#8888AA"/>
      <Setter Property="Padding"         Value="14,5"/>
      <Setter Property="FontSize"        Value="12"/>
    </Style>
  </Window.Resources>
  <Grid Margin="10">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="180"/>
    </Grid.RowDefinitions>

    <!-- ROW 0 : Header / Connect -->
    <Border Grid.Row="0" Background="#0F0F1E" CornerRadius="6" Padding="14,8" Margin="0,0,0,6">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <StackPanel Grid.Column="0" Orientation="Horizontal">
          <TextBlock Text="🔥" FontSize="22" VerticalAlignment="Center" Margin="0,0,10,0"/>
          <StackPanel VerticalAlignment="Center">
            <TextBlock Text="Palo Alto Firewall Manager" FontSize="15" FontWeight="Bold" Foreground="White"/>
            <TextBlock x:Name="txtSubtitle" Text="Not connected" FontSize="10" Foreground="#666688"/>
          </StackPanel>
        </StackPanel>
        <WrapPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center">
          <Label Content="Panorama IP:" Style="{StaticResource Lbl}"/>
          <TextBox x:Name="txtPanoramaIP" Text="10.28.90.20" Width="130" Style="{StaticResource TBox}"/>
          <Label Content="User:" Style="{StaticResource Lbl}" Margin="8,0,0,0"/>
          <TextBox x:Name="txtUsername" Text="" Width="90" Style="{StaticResource TBox}"/>
          <Label Content="Pass:" Style="{StaticResource Lbl}" Margin="6,0,0,0"/>
          <PasswordBox x:Name="pwdPassword" Width="90" Background="#1E1E30" Foreground="#E0E0F0" BorderBrush="#3A3A5C" Padding="6,3" FontSize="12" VerticalContentAlignment="Center"/>
          <Label Content="Version:" Style="{StaticResource Lbl}" Margin="8,0,0,0"/>
          <TextBox x:Name="txtVersion" Text="11.1.13-h5" Width="110" Style="{StaticResource TBox}"/>
          <Button x:Name="btnConnect"     Content="🔗 Connect"     Style="{StaticResource Btn}"      Width="95"  Margin="10,0,3,0"/>
          <Button x:Name="btnLoadDevices" Content="↻ Load Devices" Style="{StaticResource BtnGreen}" Width="115" IsEnabled="False"/>
          <Ellipse x:Name="ellStatus" Width="11" Height="11" Fill="#333355" Margin="10,0,0,0" VerticalAlignment="Center">
            <Ellipse.ToolTip><ToolTip><TextBlock x:Name="ttStatus" Text="Disconnected"/></ToolTip></Ellipse.ToolTip>
          </Ellipse>
        </WrapPanel>
      </Grid>
    </Border>

    <!-- ROW 1 : Filters -->
    <Border Grid.Row="1" Background="#0F0F1E" CornerRadius="6" Padding="12,7" Margin="0,0,0,6">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <WrapPanel Grid.Column="0" Orientation="Horizontal">
          <Label Content="Region:" Style="{StaticResource Lbl}" FontWeight="SemiBold"/>
          <CheckBox x:Name="cbUS"  Content="US"  Style="{StaticResource FCB}"/>
          <CheckBox x:Name="cbEU"  Content="EU"  Style="{StaticResource FCB}"/>
          <CheckBox x:Name="cbAU"  Content="AU"  Style="{StaticResource FCB}"/>
          <CheckBox x:Name="cbNZ"  Content="NZ"  Style="{StaticResource FCB}"/>
          <CheckBox x:Name="cbUK"  Content="UK"  Style="{StaticResource FCB}"/>
          <CheckBox x:Name="cbCH"  Content="CH"  Style="{StaticResource FCB}"/>
          <CheckBox x:Name="cbMFG" Content="MFG" Style="{StaticResource FCB}"/>
          <CheckBox x:Name="cbSHP" Content="SHP" Style="{StaticResource FCB}"/>
          <Rectangle Width="1" Fill="#333355" Margin="8,2"/>
          <Label Content="HA State:" Style="{StaticResource Lbl}" FontWeight="SemiBold"/>
          <CheckBox x:Name="cbHAActive"  Content="Active"  Style="{StaticResource FCB}"/>
          <CheckBox x:Name="cbHAPassive" Content="Passive" Style="{StaticResource FCB}"/>
          <CheckBox x:Name="cbHASingle"  Content="Single"  Style="{StaticResource FCB}"/>
          <Rectangle Width="1" Fill="#333355" Margin="8,2"/>
          <CheckBox x:Name="cbExclVer" Content="Exclude target ver" Style="{StaticResource FCB}"/>
          <Rectangle Width="1" Fill="#333355" Margin="8,2"/>
          <Label Content="Custom:" Style="{StaticResource Lbl}" FontWeight="SemiBold"/>
          <TextBox x:Name="txtCustomInclude" Width="110" Style="{StaticResource TBox}" ToolTip="Hostname must CONTAIN this text (regex ok)"/>
          <Label Content="Excl:" Style="{StaticResource Lbl}" Margin="6,0,0,0"/>
          <TextBox x:Name="txtCustomExclude" Width="110" Style="{StaticResource TBox}" ToolTip="Hostname must NOT contain this text (regex ok)"/>
        </WrapPanel>
        <StackPanel Grid.Column="1" Orientation="Horizontal">
          <Button x:Name="btnApplyFilter" Content="▶ Apply" Style="{StaticResource BtnGreen}" Padding="10,5"/>
          <Button x:Name="btnClearFilter" Content="✕ Clear" Style="{StaticResource BtnGray}"  Padding="10,5"/>
        </StackPanel>
      </Grid>
    </Border>

    <!-- ROW 2 : Stats + Quick-select -->
    <Border Grid.Row="2" Background="#0F0F1E" CornerRadius="6" Padding="12,6" Margin="0,0,0,6">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <StackPanel Grid.Column="0" Orientation="Horizontal">
          <TextBlock x:Name="txtTotal"  Text="Shown: 0"       Foreground="#8888AA" FontSize="11" VerticalAlignment="Center" Margin="0,0,14,0"/>
          <TextBlock x:Name="txtActCnt" Text="Active: 0"      Foreground="#66BB6A" FontSize="11" VerticalAlignment="Center" Margin="0,0,14,0"/>
          <TextBlock x:Name="txtPasCnt" Text="Passive: 0"     Foreground="#FFA726" FontSize="11" VerticalAlignment="Center" Margin="0,0,14,0"/>
          <TextBlock x:Name="txtSglCnt" Text="Single: 0"      Foreground="#42A5F5" FontSize="11" VerticalAlignment="Center" Margin="0,0,14,0"/>
          <TextBlock x:Name="txtUpdCnt" Text="Need update: 0" Foreground="#EF5350" FontSize="11" VerticalAlignment="Center" Margin="0,0,14,0"/>
          <TextBlock x:Name="txtSelCnt" Text="Selected: 0"    Foreground="#CE93D8" FontSize="11" FontWeight="Bold" VerticalAlignment="Center"/>
        </StackPanel>
        <WrapPanel Grid.Column="2" Orientation="Horizontal">
          <Button x:Name="btnSelAll"     Content="All"          Style="{StaticResource BtnGray}" Padding="8,4" FontSize="10"/>
          <Button x:Name="btnSelNone"    Content="None"         Style="{StaticResource BtnGray}" Padding="8,4" FontSize="10"/>
          <Button x:Name="btnSelActive"  Content="Active HA"    Style="{StaticResource BtnGray}" Padding="8,4" FontSize="10"/>
          <Button x:Name="btnSelPassive" Content="Passive HA"   Style="{StaticResource BtnGray}" Padding="8,4" FontSize="10"/>
          <Button x:Name="btnSelSingle"  Content="Single"       Style="{StaticResource BtnGray}" Padding="8,4" FontSize="10"/>
          <Button x:Name="btnSelNeedUpd" Content="Needs Update" Style="{StaticResource BtnGray}" Padding="8,4" FontSize="10"/>
          <Rectangle Width="1" Fill="#333355" Margin="6,2"/>
          <Button x:Name="btnPingStart"  Content="▶ Ping"       Style="{StaticResource BtnGreen}" Padding="8,4" FontSize="10"/>
          <Button x:Name="btnPingStop"   Content="⏹ Stop"       Style="{StaticResource BtnGray}"  Padding="8,4" FontSize="10" IsEnabled="False"/>
        </WrapPanel>
      </Grid>
    </Border>

    <!-- ROW 3 : Tabs (Devices + Licenses) -->
    <TabControl x:Name="tabMain" Grid.Row="3" Margin="0,0,0,6">
      <TabItem Header="🖥 Devices">
        <DataGrid x:Name="dgDevices" AutoGenerateColumns="False" CanUserAddRows="False" IsReadOnly="False" RowStyle="{StaticResource GridRow}">
          <DataGrid.Columns>
            <DataGridCheckBoxColumn Header="✓" Binding="{Binding Selected, UpdateSourceTrigger=PropertyChanged, Mode=TwoWay}" Width="30"/>
            <DataGridTextColumn Header="Hostname"   Binding="{Binding Hostname}"       Width="175" IsReadOnly="True"/>
            <DataGridTextColumn Header="Model"      Binding="{Binding Model}"          Width="80"  IsReadOnly="True"/>
            <DataGridTextColumn Header="SW Version" Binding="{Binding SwVersion}"      Width="110" IsReadOnly="True"/>
            <DataGridTextColumn Header="IP Address" Binding="{Binding IPAddress}"      Width="125" IsReadOnly="True"/>
            <DataGridTextColumn Header="HA State"   Binding="{Binding HAState}"        Width="80"  IsReadOnly="True"/>
            <DataGridTextColumn Header="HA Type"    Binding="{Binding HAType}"         Width="80"  IsReadOnly="True"/>
            <DataGridTextColumn Header="Sync"       Binding="{Binding HASync}"         Width="125" IsReadOnly="True"/>
            <DataGridTextColumn Header="Priority"   Binding="{Binding HAPriority}"     Width="65"  IsReadOnly="True"/>
            <DataGridTextColumn Header="Preemptive" Binding="{Binding HAPreemptive}"   Width="80"  IsReadOnly="True"/>
            <DataGridTextColumn Header="Ping"       Binding="{Binding PingStatus}"     Width="65"  IsReadOnly="True"/>
            <DataGridTextColumn Header="Latency"    Binding="{Binding PingLatency}"    Width="70"  IsReadOnly="True"/>
            <DataGridTextColumn Header="Download"   Binding="{Binding DownloadStatus}" Width="120" IsReadOnly="True"/>
            <DataGridTextColumn Header="Install"    Binding="{Binding InstallStatus}"  Width="120" IsReadOnly="True"/>
            <DataGridTextColumn Header="Serial"     Binding="{Binding Serial}"         Width="125" IsReadOnly="True"/>
          </DataGrid.Columns>
        </DataGrid>
      </TabItem>
      <TabItem Header="🔑 Licenses">
        <Grid Background="#1A1A2C">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
          </Grid.RowDefinitions>
          <Border Grid.Row="0" Background="#0F0F1E" Padding="8,6" Margin="0,0,0,2">
            <WrapPanel Orientation="Horizontal">
              <Button x:Name="btnFetchLicenses" Content="↻ Fetch Licenses (Selected)" Style="{StaticResource BtnGreen}" IsEnabled="False" Padding="12,4"/>
              <Button x:Name="btnFetchLicAll"   Content="↻ Fetch All"                 Style="{StaticResource Btn}"      IsEnabled="False" Padding="10,4" Margin="4,0"/>
              <Button x:Name="btnExportLicCSV"  Content="📥 Export CSV"               Style="{StaticResource BtnGray}"  Padding="10,4"/>
              <TextBlock x:Name="txtLicStatus" Text="" Foreground="#8888AA" FontSize="11" VerticalAlignment="Center" Margin="14,0,0,0"/>
            </WrapPanel>
          </Border>
          <DataGrid x:Name="dgLicenses" Grid.Row="1" AutoGenerateColumns="False" CanUserAddRows="False" IsReadOnly="True">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Hostname"      Binding="{Binding Hostname}"    Width="170"/>
              <DataGridTextColumn Header="Model"         Binding="{Binding Model}"       Width="75"/>
              <DataGridTextColumn Header="Serial"        Binding="{Binding Serial}"      Width="120"/>
              <DataGridTextColumn Header="WildFire"      Binding="{Binding LicWildFire}" Width="140"/>
              <DataGridTextColumn Header="DNS Security"  Binding="{Binding LicDNS}"      Width="140"/>
              <DataGridTextColumn Header="URL Filtering" Binding="{Binding LicURL}"      Width="140"/>
              <DataGridTextColumn Header="IoT Security"  Binding="{Binding LicIoT}"      Width="140"/>
              <DataGridTextColumn Header="Threat Prev"   Binding="{Binding LicThreat}"   Width="140"/>
              <DataGridTextColumn Header="Support"       Binding="{Binding LicSupport}"  Width="140"/>
            </DataGrid.Columns>
          </DataGrid>
        </Grid>
      </TabItem>
      <TabItem Header="👤 User-ID">
        <Grid Background="#1A1A2C">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <Border Grid.Row="0" Background="#0F0F1E" Padding="8,6" Margin="0,0,0,2">
            <WrapPanel Orientation="Horizontal">
              <Button x:Name="btnFetchUserID"    Content="↻ Check (Selected)" Style="{StaticResource BtnGreen}" IsEnabled="False" Padding="12,4"/>
              <Button x:Name="btnFetchUserIDAll" Content="↻ All"               Style="{StaticResource Btn}"      IsEnabled="False" Padding="10,4" Margin="4,0"/>
              <Button x:Name="btnExportUserID"   Content="📥 Export CSV"      Style="{StaticResource BtnGray}"  Padding="10,4"/>
              <TextBlock x:Name="txtUserIDStatus" Text="" Foreground="#8888AA" FontSize="11" VerticalAlignment="Center" Margin="14,0,0,0"/>
            </WrapPanel>
          </Border>
          <DataGrid x:Name="dgUserID" Grid.Row="1" AutoGenerateColumns="False" CanUserAddRows="False" IsReadOnly="True">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Hostname"    Binding="{Binding Hostname}"       Width="180"/>
              <DataGridTextColumn Header="IP Mappings" Binding="{Binding IPMappings}"     Width="110"/>
              <DataGridTextColumn Header="Agents"      Binding="{Binding AgentTotal}"     Width="80"/>
              <DataGridTextColumn Header="Connected"   Binding="{Binding AgentConnected}" Width="100"/>
              <DataGridTextColumn Header="Groups"      Binding="{Binding GroupCount}"     Width="80"/>
              <DataGridTextColumn Header="Issues"      Binding="{Binding Issues}"         Width="*"/>
            </DataGrid.Columns>
          </DataGrid>
        </Grid>
      </TabItem>
      <TabItem Header="📡 ARP">
        <Grid Background="#1A1A2C">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <Border Grid.Row="0" Background="#0F0F1E" Padding="8,6" Margin="0,0,0,2">
            <WrapPanel Orientation="Horizontal">
              <Button x:Name="btnFetchARP"    Content="↻ Fetch ARP (Selected)" Style="{StaticResource BtnGreen}" IsEnabled="False" Padding="12,4"/>
              <Button x:Name="btnFetchARPAll" Content="↻ All"                  Style="{StaticResource Btn}"      IsEnabled="False" Padding="10,4" Margin="4,0"/>
              <Button x:Name="btnExportARP"   Content="📥 Export CSV"          Style="{StaticResource BtnGray}"  Padding="10,4"/>
              <Label Content="Filter IP/MAC:" Style="{StaticResource Lbl}" Margin="10,0,0,0"/>
              <TextBox x:Name="txtARPFilter" Width="160" Style="{StaticResource TBox}" ToolTip="Regex matched against IP and MAC"/>
              <Button x:Name="btnARPClearFilter" Content="✕" Style="{StaticResource BtnGray}" Padding="6,4"/>
              <TextBlock x:Name="txtARPStatus" Text="" Foreground="#8888AA" FontSize="11" VerticalAlignment="Center" Margin="14,0,0,0"/>
            </WrapPanel>
          </Border>
          <DataGrid x:Name="dgARP" Grid.Row="1" AutoGenerateColumns="False" CanUserAddRows="False" IsReadOnly="True">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Hostname"  Binding="{Binding Hostname}"  Width="180"/>
              <DataGridTextColumn Header="Interface" Binding="{Binding Interface}" Width="120"/>
              <DataGridTextColumn Header="IP"        Binding="{Binding IP}"        Width="140"/>
              <DataGridTextColumn Header="MAC"       Binding="{Binding MAC}"       Width="150"/>
              <DataGridTextColumn Header="Port"      Binding="{Binding Port}"      Width="100"/>
              <DataGridTextColumn Header="Status"    Binding="{Binding Status}"    Width="70"/>
              <DataGridTextColumn Header="TTL"       Binding="{Binding TTL}"       Width="*"/>
            </DataGrid.Columns>
          </DataGrid>
        </Grid>
      </TabItem>
      <TabItem Header="🔒 IPsec">
        <Grid Background="#1A1A2C">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <Border Grid.Row="0" Background="#0F0F1E" Padding="8,6" Margin="0,0,0,2">
            <WrapPanel Orientation="Horizontal">
              <Button x:Name="btnFetchIPsec"    Content="↻ Fetch IPsec (Selected)" Style="{StaticResource BtnGreen}" IsEnabled="False" Padding="12,4"/>
              <Button x:Name="btnFetchIPsecAll" Content="↻ All"                    Style="{StaticResource Btn}"      IsEnabled="False" Padding="10,4" Margin="4,0"/>
              <Button x:Name="btnExportIPsec"   Content="📥 Export CSV"            Style="{StaticResource BtnGray}"  Padding="10,4"/>
              <TextBlock x:Name="txtIPsecStatus" Text="" Foreground="#8888AA" FontSize="11" VerticalAlignment="Center" Margin="14,0,0,0"/>
            </WrapPanel>
          </Border>
          <DataGrid x:Name="dgIPsec" Grid.Row="1" AutoGenerateColumns="False" CanUserAddRows="False" IsReadOnly="True">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Hostname" Binding="{Binding Hostname}"  Width="180"/>
              <DataGridTextColumn Header="Tunnel"   Binding="{Binding Name}"      Width="220"/>
              <DataGridTextColumn Header="Peer"     Binding="{Binding Peer}"      Width="160"/>
              <DataGridTextColumn Header="GwName"   Binding="{Binding GwName}"    Width="180"/>
              <DataGridTextColumn Header="State"    Binding="{Binding State}"     Width="100"/>
              <DataGridTextColumn Header="Algorithm" Binding="{Binding Algorithm}" Width="*"/>
            </DataGrid.Columns>
          </DataGrid>
        </Grid>
      </TabItem>
      <TabItem Header="🛣 Routes">
        <Grid Background="#1A1A2C">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <Border Grid.Row="0" Background="#0F0F1E" Padding="8,6" Margin="0,0,0,2">
            <WrapPanel Orientation="Horizontal">
              <Button x:Name="btnFetchRoutes"    Content="↻ Fetch Routes (Selected)" Style="{StaticResource BtnGreen}" IsEnabled="False" Padding="12,4"/>
              <Button x:Name="btnFetchRoutesAll" Content="↻ All"                     Style="{StaticResource Btn}"      IsEnabled="False" Padding="10,4" Margin="4,0"/>
              <Button x:Name="btnExportRoutes"   Content="📥 Export CSV"             Style="{StaticResource BtnGray}"  Padding="10,4"/>
              <Label Content="Dest contains:" Style="{StaticResource Lbl}" Margin="10,0,0,0"/>
              <TextBox x:Name="txtRouteFilter" Width="160" Style="{StaticResource TBox}" ToolTip="Regex matched against destination"/>
              <Button x:Name="btnRouteClearFilter" Content="✕" Style="{StaticResource BtnGray}" Padding="6,4"/>
              <TextBlock x:Name="txtRoutesStatus" Text="" Foreground="#8888AA" FontSize="11" VerticalAlignment="Center" Margin="14,0,0,0"/>
            </WrapPanel>
          </Border>
          <DataGrid x:Name="dgRoutes" Grid.Row="1" AutoGenerateColumns="False" CanUserAddRows="False" IsReadOnly="True">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Hostname"    Binding="{Binding Hostname}"    Width="180"/>
              <DataGridTextColumn Header="VR"          Binding="{Binding VR}"          Width="90"/>
              <DataGridTextColumn Header="Destination" Binding="{Binding Destination}" Width="170"/>
              <DataGridTextColumn Header="Next Hop"    Binding="{Binding NextHop}"     Width="140"/>
              <DataGridTextColumn Header="Metric"      Binding="{Binding Metric}"      Width="60"/>
              <DataGridTextColumn Header="Flags"       Binding="{Binding Flags}"       Width="80"/>
              <DataGridTextColumn Header="Age"         Binding="{Binding Age}"         Width="80"/>
              <DataGridTextColumn Header="Interface"   Binding="{Binding Interface}"   Width="*"/>
            </DataGrid.Columns>
          </DataGrid>
        </Grid>
      </TabItem>
      <TabItem Header="🔓 Locks">
        <Grid Background="#1A1A2C">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <Border Grid.Row="0" Background="#0F0F1E" Padding="8,6" Margin="0,0,0,2">
            <WrapPanel Orientation="Horizontal">
              <Button x:Name="btnFetchLocks"    Content="↻ Check Locks (Selected)"   Style="{StaticResource BtnGreen}" IsEnabled="False" Padding="12,4"/>
              <Button x:Name="btnFetchLocksAll" Content="↻ All"                       Style="{StaticResource Btn}"      IsEnabled="False" Padding="10,4" Margin="4,0"/>
              <Button x:Name="btnRemoveLocks"   Content="✕ Remove ALL on Selected"   Style="{StaticResource BtnRed}"   IsEnabled="False" Padding="10,4" Margin="10,0,0,0"/>
              <Button x:Name="btnExportLocks"   Content="📥 Export CSV"              Style="{StaticResource BtnGray}"  Padding="10,4"/>
              <TextBlock x:Name="txtLocksStatus" Text="" Foreground="#8888AA" FontSize="11" VerticalAlignment="Center" Margin="14,0,0,0"/>
            </WrapPanel>
          </Border>
          <DataGrid x:Name="dgLocks" Grid.Row="1" AutoGenerateColumns="False" CanUserAddRows="False" IsReadOnly="True">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Hostname" Binding="{Binding Hostname}" Width="180"/>
              <DataGridTextColumn Header="Type"     Binding="{Binding LockType}" Width="100"/>
              <DataGridTextColumn Header="Admin"    Binding="{Binding Admin}"    Width="150"/>
              <DataGridTextColumn Header="Vsys"     Binding="{Binding Vsys}"     Width="80"/>
              <DataGridTextColumn Header="Created"  Binding="{Binding Created}"  Width="170"/>
              <DataGridTextColumn Header="Comment"  Binding="{Binding Comment}"  Width="*"/>
            </DataGrid.Columns>
          </DataGrid>
        </Grid>
      </TabItem>
      <TabItem Header="📋 EDLs">
        <Grid Background="#1A1A2C">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <Border Grid.Row="0" Background="#0F0F1E" Padding="8,6" Margin="0,0,0,2">
            <WrapPanel Orientation="Horizontal">
              <Button x:Name="btnFetchEDLs"   Content="↻ Load EDL List"                       Style="{StaticResource BtnGreen}" IsEnabled="False" Padding="12,4"/>
              <Button x:Name="btnRefreshEDLs" Content="↻ Refresh Checked on Selected Devices" Style="{StaticResource BtnAmber}" IsEnabled="False" Padding="12,4" Margin="10,0,0,0"/>
              <Button x:Name="btnSelAllEDLs"  Content="All"  Style="{StaticResource BtnGray}" Padding="8,4" Margin="10,0,0,0"/>
              <Button x:Name="btnSelNoneEDLs" Content="None" Style="{StaticResource BtnGray}" Padding="8,4"/>
              <TextBlock x:Name="txtEDLStatus" Text="" Foreground="#8888AA" FontSize="11" VerticalAlignment="Center" Margin="14,0,0,0"/>
            </WrapPanel>
          </Border>
          <DataGrid x:Name="dgEDLs" Grid.Row="1" AutoGenerateColumns="False" CanUserAddRows="False">
            <DataGrid.Columns>
              <DataGridCheckBoxColumn Header="✓" Binding="{Binding Selected, UpdateSourceTrigger=PropertyChanged, Mode=TwoWay}" Width="30"/>
              <DataGridTextColumn Header="Name"        Binding="{Binding Name}"        Width="260" IsReadOnly="True"/>
              <DataGridTextColumn Header="Type"        Binding="{Binding Type}"        Width="60"  IsReadOnly="True"/>
              <DataGridTextColumn Header="URL"         Binding="{Binding Url}"         Width="350" IsReadOnly="True"/>
              <DataGridTextColumn Header="Description" Binding="{Binding Description}" Width="*"   IsReadOnly="True"/>
            </DataGrid.Columns>
          </DataGrid>
        </Grid>
      </TabItem>
    </TabControl>

    <!-- ROW 4 : Action Bar -->
    <Border Grid.Row="4" Background="#0F0F1E" CornerRadius="6" Padding="10,7" Margin="0,0,0,6">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <WrapPanel Grid.Column="0" Orientation="Horizontal">
          <Label Content="HA:" Style="{StaticResource Lbl}" FontWeight="SemiBold"/>
          <Button x:Name="btnRefreshHA" Content="↻ Refresh HA"    Style="{StaticResource Btn}"      IsEnabled="False"/>
          <Button x:Name="btnSyncHA"    Content="⟳ Sync Config"    Style="{StaticResource Btn}"      IsEnabled="False"/>
          <Button x:Name="btnSetPri70"  Content="↑ Pri 70"        Style="{StaticResource BtnAmber}" IsEnabled="False"/>
          <Button x:Name="btnSetPri90"  Content="↑ Pri 90 (1°)"   Style="{StaticResource BtnAmber}" IsEnabled="False"/>
          <Button x:Name="btnSetPri110" Content="↓ Pri 110 (2°)"  Style="{StaticResource BtnAmber}" IsEnabled="False"/>
          <Button x:Name="btnSetPri130" Content="↓ Pri 130 (3°)"  Style="{StaticResource BtnAmber}" IsEnabled="False"/>
          <Rectangle Width="1" Fill="#333355" Margin="6,2"/>
          <Label Content="SW:" Style="{StaticResource Lbl}" FontWeight="SemiBold"/>
          <Button x:Name="btnCheckDl"   Content="🔍 Check &amp; Download" Style="{StaticResource BtnGreen}" IsEnabled="False"/>
          <Button x:Name="btnInstall"   Content="⬇ Install"               Style="{StaticResource BtnGreen}" IsEnabled="False"/>
          <Button x:Name="btnCheckJobs" Content="📋 Job Status"            Style="{StaticResource Btn}"      IsEnabled="False"/>
        </WrapPanel>
        <Button x:Name="btnReboot" Grid.Column="1" Content="⚡ Reboot Selected" Style="{StaticResource BtnRed}" IsEnabled="False" Padding="14,5"/>
      </Grid>
    </Border>

    <!-- ROW 5 : Log -->
    <Border Grid.Row="5" Background="#080810" CornerRadius="6" Padding="4">
      <Grid>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        <StackPanel Grid.Row="0" Orientation="Horizontal" Margin="8,4,8,2">
          <TextBlock Text="● Operation Log" Foreground="#5555AA" FontSize="10" FontWeight="SemiBold" VerticalAlignment="Center"/>
          <Button x:Name="btnClearLog" Content="Clear" Margin="10,0,0,0" Padding="6,1" Background="#1A1A2C" Foreground="#666688" BorderThickness="0" FontSize="10" Cursor="Hand"/>
        </StackPanel>
        <ScrollViewer Grid.Row="1" x:Name="svLog" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
          <TextBlock x:Name="txtLog" FontFamily="Consolas" FontSize="11" Foreground="#66FF88" TextWrapping="Wrap" Padding="8,2" Background="Transparent"/>
        </ScrollViewer>
      </Grid>
    </Border>
  </Grid>
</Window>
'@

# ── Parse XAML & get controls ────────────────────────────────
$Reader  = [System.Xml.XmlNodeReader]::new($XAML)
$Window  = [System.Windows.Markup.XamlReader]::Load($Reader)
function Ctrl($n) { $Window.FindName($n) }

$txtPanoramaIP    = Ctrl 'txtPanoramaIP'
$txtUsername      = Ctrl 'txtUsername'
$pwdPassword      = Ctrl 'pwdPassword'
$txtVersion       = Ctrl 'txtVersion'
$txtSubtitle      = Ctrl 'txtSubtitle'
$ellStatus        = Ctrl 'ellStatus'
$ttStatus         = Ctrl 'ttStatus'
$btnConnect       = Ctrl 'btnConnect'
$btnLoadDevices   = Ctrl 'btnLoadDevices'
$cbUS=Ctrl 'cbUS'; $cbEU=Ctrl 'cbEU'; $cbAU=Ctrl 'cbAU'; $cbNZ=Ctrl 'cbNZ'
$cbUK=Ctrl 'cbUK'; $cbCH=Ctrl 'cbCH'; $cbMFG=Ctrl 'cbMFG'; $cbSHP=Ctrl 'cbSHP'
$cbHAActive=Ctrl 'cbHAActive'; $cbHAPassive=Ctrl 'cbHAPassive'; $cbHASingle=Ctrl 'cbHASingle'
$cbExclVer=Ctrl 'cbExclVer'
$txtCustomInclude=Ctrl 'txtCustomInclude'; $txtCustomExclude=Ctrl 'txtCustomExclude'
$btnApplyFilter=Ctrl 'btnApplyFilter'; $btnClearFilter=Ctrl 'btnClearFilter'
$txtTotal=Ctrl 'txtTotal'; $txtActCnt=Ctrl 'txtActCnt'; $txtPasCnt=Ctrl 'txtPasCnt'
$txtSglCnt=Ctrl 'txtSglCnt'; $txtUpdCnt=Ctrl 'txtUpdCnt'; $txtSelCnt=Ctrl 'txtSelCnt'
$btnSelAll=Ctrl 'btnSelAll'; $btnSelNone=Ctrl 'btnSelNone'
$btnSelActive=Ctrl 'btnSelActive'; $btnSelPassive=Ctrl 'btnSelPassive'
$btnSelSingle=Ctrl 'btnSelSingle'; $btnSelNeedUpd=Ctrl 'btnSelNeedUpd'
$btnPingStart=Ctrl 'btnPingStart'; $btnPingStop=Ctrl 'btnPingStop'
$tabMain=Ctrl 'tabMain'; $dgDevices=Ctrl 'dgDevices'
$btnRefreshHA=Ctrl 'btnRefreshHA'; $btnSyncHA=Ctrl 'btnSyncHA'
$btnSetPri70=Ctrl 'btnSetPri70'; $btnSetPri90=Ctrl 'btnSetPri90'; $btnSetPri110=Ctrl 'btnSetPri110'; $btnSetPri130=Ctrl 'btnSetPri130'
$btnCheckDl=Ctrl 'btnCheckDl'; $btnInstall=Ctrl 'btnInstall'
$btnCheckJobs=Ctrl 'btnCheckJobs'; $btnReboot=Ctrl 'btnReboot'
$btnFetchLicenses=Ctrl 'btnFetchLicenses'; $btnFetchLicAll=Ctrl 'btnFetchLicAll'
$btnExportLicCSV=Ctrl 'btnExportLicCSV'; $txtLicStatus=Ctrl 'txtLicStatus'
$dgLicenses=Ctrl 'dgLicenses'

# New-tools controls
$btnFetchUserID=Ctrl 'btnFetchUserID'; $btnFetchUserIDAll=Ctrl 'btnFetchUserIDAll'
$btnExportUserID=Ctrl 'btnExportUserID'; $txtUserIDStatus=Ctrl 'txtUserIDStatus'; $dgUserID=Ctrl 'dgUserID'

$btnFetchARP=Ctrl 'btnFetchARP'; $btnFetchARPAll=Ctrl 'btnFetchARPAll'
$btnExportARP=Ctrl 'btnExportARP'; $txtARPFilter=Ctrl 'txtARPFilter'
$btnARPClearFilter=Ctrl 'btnARPClearFilter'; $txtARPStatus=Ctrl 'txtARPStatus'; $dgARP=Ctrl 'dgARP'

$btnFetchIPsec=Ctrl 'btnFetchIPsec'; $btnFetchIPsecAll=Ctrl 'btnFetchIPsecAll'
$btnExportIPsec=Ctrl 'btnExportIPsec'; $txtIPsecStatus=Ctrl 'txtIPsecStatus'; $dgIPsec=Ctrl 'dgIPsec'

$btnFetchRoutes=Ctrl 'btnFetchRoutes'; $btnFetchRoutesAll=Ctrl 'btnFetchRoutesAll'
$btnExportRoutes=Ctrl 'btnExportRoutes'; $txtRouteFilter=Ctrl 'txtRouteFilter'
$btnRouteClearFilter=Ctrl 'btnRouteClearFilter'; $txtRoutesStatus=Ctrl 'txtRoutesStatus'; $dgRoutes=Ctrl 'dgRoutes'

$btnFetchLocks=Ctrl 'btnFetchLocks'; $btnFetchLocksAll=Ctrl 'btnFetchLocksAll'
$btnRemoveLocks=Ctrl 'btnRemoveLocks'; $btnExportLocks=Ctrl 'btnExportLocks'
$txtLocksStatus=Ctrl 'txtLocksStatus'; $dgLocks=Ctrl 'dgLocks'

$btnFetchEDLs=Ctrl 'btnFetchEDLs'; $btnRefreshEDLs=Ctrl 'btnRefreshEDLs'
$btnSelAllEDLs=Ctrl 'btnSelAllEDLs'; $btnSelNoneEDLs=Ctrl 'btnSelNoneEDLs'
$txtEDLStatus=Ctrl 'txtEDLStatus'; $dgEDLs=Ctrl 'dgEDLs'
$txtLog=Ctrl 'txtLog'; $svLog=Ctrl 'svLog'; $btnClearLog=Ctrl 'btnClearLog'

# ── Global state ─────────────────────────────────────────────
$script:AllDevices  = [System.Collections.Generic.List[object]]::new()
$script:DisplayColl = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$script:Connected   = $false
$script:PingCtrl       = [System.Collections.Hashtable]::Synchronized(@{ Stop = $false; Running = $false })
$script:RebootPollCtrl = [System.Collections.Hashtable]::Synchronized(@{ Stop = $false; Running = $false })

$dgDevices.ItemsSource  = $script:DisplayColl
$dgLicenses.ItemsSource = $script:DisplayColl   # matrix uses live devices

# New-tools collections. ARP/Routes keep an unfiltered backing list + a visible
# ObservableCollection so the filter textbox can hide rows without losing data.
$script:ColUserID    = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$script:ColARPAll    = [System.Collections.Generic.List[object]]::new()
$script:ColARP       = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$script:ColIPsec     = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$script:ColRoutesAll = [System.Collections.Generic.List[object]]::new()
$script:ColRoutes    = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$script:ColLocks     = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$script:ColEDLs      = [System.Collections.ObjectModel.ObservableCollection[object]]::new()

$dgUserID.ItemsSource = $script:ColUserID
$dgARP.ItemsSource    = $script:ColARP
$dgIPsec.ItemsSource  = $script:ColIPsec
$dgRoutes.ItemsSource = $script:ColRoutes
$dgLocks.ItemsSource  = $script:ColLocks
$dgEDLs.ItemsSource   = $script:ColEDLs

# ── Helpers ──────────────────────────────────────────────────
function Write-Log {
    param([string]$Msg)
    $ts   = (Get-Date).ToString('HH:mm:ss')
    $line = "[$ts] $Msg`n"
    $Window.Dispatcher.Invoke([action]{
        $txtLog.Text += $line
        $svLog.ScrollToBottom()
    }, 'Normal')
}
function UI { param([scriptblock]$Block) $Window.Dispatcher.Invoke($Block, 'Normal') }

function Update-Stats {
    UI {
        $col = $script:DisplayColl
        $txtTotal.Text  = "Shown: $($col.Count)"
        $txtActCnt.Text = "Active: $(($col | Where-Object HAState -eq 'active').Count)"
        $txtPasCnt.Text = "Passive: $(($col | Where-Object HAState -eq 'passive').Count)"
        $txtSglCnt.Text = "Single: $(($col | Where-Object { $_.HAState -eq '' }).Count)"
        $txtUpdCnt.Text = "Need update: $(($col | Where-Object IsTargetVer -eq $false).Count)"
        $txtSelCnt.Text = "Selected: $(($col | Where-Object Selected).Count)"
    }
}

function Apply-Filter {
    $incl      = $txtCustomInclude.Text.Trim()
    $excl      = $txtCustomExclude.Text.Trim()
    $anyRegion = ($cbUS.IsChecked -or $cbEU.IsChecked -or $cbAU.IsChecked -or
                  $cbNZ.IsChecked -or $cbUK.IsChecked -or $cbCH.IsChecked -or
                  $cbMFG.IsChecked -or $cbSHP.IsChecked)
    $anyHA     = ($cbHAActive.IsChecked -or $cbHAPassive.IsChecked -or $cbHASingle.IsChecked)
    $filtered = $script:AllDevices | Where-Object {
        $d = $_
        if ($anyRegion) {
            $r = (($cbUS.IsChecked  -and $d.Hostname -match 'US')  -or
                  ($cbEU.IsChecked  -and $d.Hostname -match 'EU')  -or
                  ($cbAU.IsChecked  -and $d.Hostname -match 'AU')  -or
                  ($cbNZ.IsChecked  -and $d.Hostname -match 'NZ')  -or
                  ($cbUK.IsChecked  -and $d.Hostname -match 'UK')  -or
                  ($cbCH.IsChecked  -and $d.Hostname -match 'CH')  -or
                  ($cbMFG.IsChecked -and $d.Hostname -match 'MFG') -or
                  ($cbSHP.IsChecked -and $d.Hostname -match 'SHP'))
            if (-not $r) { return $false }
        }
        if ($anyHA) {
            $r = (($cbHAActive.IsChecked  -and $d.HAState -eq 'active')  -or
                  ($cbHAPassive.IsChecked -and $d.HAState -eq 'passive') -or
                  ($cbHASingle.IsChecked  -and $d.HAState -eq ''))
            if (-not $r) { return $false }
        }
        if ($cbExclVer.IsChecked -and $d.IsTargetVer)      { return $false }
        if ($incl -ne '' -and $d.Hostname -notmatch $incl) { return $false }
        if ($excl -ne '' -and $d.Hostname -match $excl)    { return $false }
        return $true
    }
    UI {
        $script:DisplayColl.Clear()
        foreach ($d in $filtered) { $script:DisplayColl.Add($d) }
        Update-Stats
    }
}

function Set-ActionButtons([bool]$enabled) {
    UI {
        foreach ($btn in @($btnRefreshHA,$btnSyncHA,$btnSetPri70,$btnSetPri90,$btnSetPri110,$btnSetPri130,
                           $btnCheckDl,$btnInstall,$btnCheckJobs,$btnReboot,
                           $btnFetchLicenses,$btnFetchLicAll,
                           $btnFetchUserID,$btnFetchUserIDAll,
                           $btnFetchARP,$btnFetchARPAll,
                           $btnFetchIPsec,$btnFetchIPsecAll,
                           $btnFetchRoutes,$btnFetchRoutesAll,
                           $btnFetchLocks,$btnFetchLocksAll,$btnRemoveLocks,
                           $btnFetchEDLs,$btnRefreshEDLs)) {
            $btn.IsEnabled = $enabled
        }
    }
}

# ── Connect ──────────────────────────────────────────────────
$btnConnect.Add_Click({
    $ip   = $txtPanoramaIP.Text.Trim()
    $user = $txtUsername.Text.Trim()
    $pass = $pwdPassword.Password
    if ($ip   -eq '') { [System.Windows.MessageBox]::Show("Enter Panorama IP.", "Missing","OK","Warning")|Out-Null; return }
    if ($user -eq '') { [System.Windows.MessageBox]::Show("Enter username.",    "Missing","OK","Warning")|Out-Null; return }
    if ($pass -eq '') { [System.Windows.MessageBox]::Show("Enter password.",    "Missing","OK","Warning")|Out-Null; return }

    $btnConnect.IsEnabled = $false
    $txtSubtitle.Text     = "Connecting to $ip as $user..."
    $ellStatus.Fill       = [System.Windows.Media.Brushes]::DarkOrange

    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('ip',            $ip)
    $rs.SessionStateProxy.SetVariable('user',          $user)
    $rs.SessionStateProxy.SetVariable('plainPass',     $pass)
    $rs.SessionStateProxy.SetVariable('Window',        $Window)
    $rs.SessionStateProxy.SetVariable('btnConnect',    $btnConnect)
    $rs.SessionStateProxy.SetVariable('btnLoadDevices',$btnLoadDevices)
    $rs.SessionStateProxy.SetVariable('txtSubtitle',   $txtSubtitle)
    $rs.SessionStateProxy.SetVariable('ellStatus',     $ellStatus)
    $rs.SessionStateProxy.SetVariable('ttStatus',      $ttStatus)
    $rs.SessionStateProxy.SetVariable('writeLogFn',    ${function:Write-Log})

    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        $sec  = ConvertTo-SecureString $plainPass -AsPlainText -Force
        $cred = [System.Management.Automation.PSCredential]::new($user, $sec)
        $ok   = $false
        foreach ($attempt in @('Credentials','Credential','None')) {
            try {
                switch ($attempt) {
                    'Credentials' { Invoke-PANKeyGen -Addresses $ip -Credentials $cred -SkipCertificateCheck -ErrorAction Stop | Out-Null }
                    'Credential'  { Invoke-PANKeyGen -Addresses $ip -Credential  $cred -SkipCertificateCheck -ErrorAction Stop | Out-Null }
                    'None'        { Invoke-PANKeyGen -Addresses $ip               -SkipCertificateCheck -ErrorAction Stop | Out-Null }
                }
                Log "OK Connected (attempt: $attempt)."
                $ok = $true; break
            } catch { Log "  [$attempt] $($_.Exception.Message)" }
        }
        $Window.Dispatcher.Invoke([action]{
            if ($ok) {
                $ellStatus.Fill           = [System.Windows.Media.Brushes]::LimeGreen
                $txtSubtitle.Text         = "Connected to $ip as $user"
                $ttStatus.Text            = "Connected"
                $btnLoadDevices.IsEnabled = $true
            } else {
                $ellStatus.Fill   = [System.Windows.Media.Brushes]::Red
                $txtSubtitle.Text = "Connection failed - check log"
                $ttStatus.Text    = "Failed"
            }
            $btnConnect.IsEnabled = $true
        }, 'Normal')
    })
    [void]$ps.BeginInvoke()
})

# ── Load Devices (single runspace, inline HA fetch — OLD pattern) ────────────
$btnLoadDevices.Add_Click({
    $ip  = $txtPanoramaIP.Text.Trim()
    $ver = $txtVersion.Text.Trim()
    $btnLoadDevices.IsEnabled = $false
    $txtSubtitle.Text         = "Loading devices..."

    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('ip',              $ip)
    $rs.SessionStateProxy.SetVariable('ver',             $ver)
    $rs.SessionStateProxy.SetVariable('Window',          $Window)
    $rs.SessionStateProxy.SetVariable('AllDevices',      $script:AllDevices)
    $rs.SessionStateProxy.SetVariable('DisplayColl',     $script:DisplayColl)
    $rs.SessionStateProxy.SetVariable('btnLoadDevices',  $btnLoadDevices)
    $rs.SessionStateProxy.SetVariable('txtSubtitle',     $txtSubtitle)
    $rs.SessionStateProxy.SetVariable('writeLogFn',      ${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('updateStatsFn',   ${function:Update-Stats})
    $rs.SessionStateProxy.SetVariable('setActionFn',     ${function:Set-ActionButtons})

    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        try {
            Log "Querying connected devices..."
            $raw = (Invoke-PANOperation -SkipCertificateCheck `
                        -Command "<show><devices><connected></connected></devices></show>").result.devices.entry
            if (-not $raw) { Log "No devices returned."; UI { $btnLoadDevices.IsEnabled=$true }; return }
            Log "Got $($raw.Count) device(s). Populating grid first, then fetching HA inline..."

            # PHASE 1: build all FirewallDevice objects (basic HA state included — it
            # comes for FREE in the <show><devices><connected> response, no extra round-
            # trip needed) and push to grid so the user sees rows immediately with
            # active/passive coloring.
            $built = [System.Collections.Generic.List[object]]::new()
            foreach ($d in $raw) {
                $dev = [FirewallDevice]::new()
                $dev.Hostname    = [string]$d.hostname
                $dev.Model       = [string]$d.model
                $dev.Serial      = [string]$d.serial
                $dev.IPAddress   = [string]$d.'ip-address'
                $dev.SwVersion   = [string]$d.'sw-version'
                $dev.IsTargetVer = ($dev.SwVersion -eq $ver)
                try {
                    $haState = [string]$d.ha.state
                    if ($haState) { $dev.HAState = $haState }
                } catch {}
                $built.Add($dev)
            }
            UI {
                $AllDevices.Clear(); $DisplayColl.Clear()
                foreach ($d in $built) { $AllDevices.Add($d); $DisplayColl.Add($d) }
                & $updateStatsFn
                & $setActionFn $true
                $btnLoadDevices.IsEnabled = $true
                $txtSubtitle.Text = "Loaded $($AllDevices.Count) device(s) - fetching HA in background..."
            }
            Log "Grid populated. Fetching HA per device ($($built.Count) total)..."

            # PHASE 2: walk devices one by one and update HA fields live as queries return.
            # Each property assignment fires INotifyPropertyChanged so the grid row updates.
            $ok = 0
            foreach ($dev in $built) {
                try {
                    $ha = Invoke-PANOperation -SkipCertificateCheck `
                            -Command ("<show><high-availability><state/></high-availability></show>&target=" + $dev.Serial)
                    $g  = $ha.result.group
                    if ($g) {
                        $li = $g.'local-info'
                        $st = [string]$li.state
                        $tp = [string]$g.mode
                        $sy = [string]$g.'running-sync'
                        $pr = [string]$li.priority
                        $pe = [string]$li.preemptive
                        UI { $dev.HAState=$st; $dev.HAType=$tp; $dev.HASync=$sy; $dev.HAPriority=$pr; $dev.HAPreemptive=$pe }
                    }
                    $ok++
                } catch {
                    Log "  HA $($dev.Hostname): $($_.Exception.Message)"
                }
            }
            UI {
                & $updateStatsFn
                $txtSubtitle.Text = "Loaded $($AllDevices.Count) device(s) - HA: $ok / $($built.Count)"
            }
            Log "Done. HA fetched for $ok / $($built.Count) device(s)."
        } catch {
            Log "Error loading devices: $($_.Exception.Message)"
            UI { $btnLoadDevices.IsEnabled = $true }
        }
    })
    [void]$ps.BeginInvoke()
})

# ── Refresh HA for selected ──────────────────────────────────
$btnRefreshHA.Add_Click({
    $sel = @($script:DisplayColl | Where-Object Selected)
    if ($sel.Count -eq 0) { Write-Log "No devices selected."; return }
    Write-Log "Refreshing HA for $($sel.Count) device(s)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('sel',$sel)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('updateStatsFn',${function:Update-Stats})
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        foreach ($dev in $sel) {
            try {
                $ha = Invoke-PANOperation -SkipCertificateCheck `
                        -Command ("<show><high-availability><state/></high-availability></show>&target=" + $dev.Serial)
                $g  = $ha.result.group
                if ($g) {
                    $li = $g.'local-info'
                    $st=[string]$li.state; $tp=[string]$g.mode; $sy=[string]$g.'running-sync'
                    $pr=[string]$li.priority; $pe=[string]$li.preemptive
                    UI { $dev.HAState=$st; $dev.HAType=$tp; $dev.HASync=$sy; $dev.HAPriority=$pr; $dev.HAPreemptive=$pe }
                    Log "  $($dev.Hostname) -> HA:$st  pri:$pr"
                } else {
                    UI { $dev.HAState=''; $dev.HAType=''; $dev.HASync=''; $dev.HAPriority=''; $dev.HAPreemptive='' }
                }
            } catch { Log "  $($dev.Hostname) - $($_.Exception.Message)" }
        }
        UI { & $updateStatsFn }
        Log "HA refresh done."
    })
    [void]$ps.BeginInvoke()
})

# ── Sync HA config (active -> passive) ──────────────────────
$btnSyncHA.Add_Click({
    $sel = @($script:DisplayColl | Where-Object { $_.Selected -and $_.HAState -eq 'active' })
    if ($sel.Count -eq 0) { Write-Log "Select active HA devices to sync."; return }
    Write-Log "Syncing HA config for $($sel.Count) active device(s)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('sel',$sel)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        foreach ($dev in $sel) {
            try {
                $r = Invoke-PANOperation -Command "<request><high-availability><sync-to-remote><running-config/></sync-to-remote></high-availability></request>" -Target $dev.Serial
                Log "  $($dev.Hostname) -> $($r.msg.line)"
            } catch { Log "  $($dev.Hostname) - $($_.Exception.Message)" }
        }
        Log "Sync requests sent."
    })
    [void]$ps.BeginInvoke()
})

# ── Set HA priority ──────────────────────────────────────────
function Set-HAPriority([string]$priority) {
    $sel = @($script:DisplayColl | Where-Object Selected)
    if ($sel.Count -eq 0) { Write-Log "No devices selected."; return }
    $preemptive = 'yes'  # Always preemptive — never flip back to 'no' regardless of priority.
    Write-Log "Setting HA priority=$priority preemptive=$preemptive on $($sel.Count) device(s)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('sel',$sel)
    $rs.SessionStateProxy.SetVariable('priority',$priority)
    $rs.SessionStateProxy.SetVariable('preemptive',$preemptive)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        $cfg   = "<preemptive>$preemptive</preemptive><device-priority>$priority</device-priority>"
        $xpath = '/config/devices/entry/deviceconfig/high-availability/group/election-option'
        foreach ($dev in $sel) {
            try {
                $r = Set-PANConfig -Data $cfg -Target $dev.Serial -XPath $xpath
                if ($r.status -eq 'success') {
                    $c = Invoke-PANCommit -Target $dev.Serial
                    if ($c.status -eq 'success') {
                        Log "  $($dev.Hostname) -> priority $priority, committed"
                        $Window.Dispatcher.Invoke([action]{ $dev.HAPriority=$priority; $dev.HAPreemptive=$preemptive }, 'Normal')
                    } else { Log "  $($dev.Hostname) commit failed" }
                } else { Log "  $($dev.Hostname) set failed: $($r.msg)" }
            } catch { Log "  $($dev.Hostname) - $($_.Exception.Message)" }
        }
        Log "Priority update done."
    })
    [void]$ps.BeginInvoke()
}
$btnSetPri70.Add_Click({  Set-HAPriority '70'  })
$btnSetPri90.Add_Click({  Set-HAPriority '90'  })
$btnSetPri110.Add_Click({ Set-HAPriority '110' })
$btnSetPri130.Add_Click({ Set-HAPriority '130' })

# ── Filter / selection helpers ───────────────────────────────
$btnApplyFilter.Add_Click({ Apply-Filter })
$btnClearFilter.Add_Click({
    foreach ($cb in @($cbUS,$cbEU,$cbAU,$cbNZ,$cbUK,$cbCH,$cbMFG,$cbSHP,$cbHAActive,$cbHAPassive,$cbHASingle,$cbExclVer)) { $cb.IsChecked=$false }
    $txtCustomInclude.Text=''; $txtCustomExclude.Text=''
    Apply-Filter
})
$btnSelAll.Add_Click({     foreach ($d in $script:DisplayColl) { $d.Selected=$true  }; Update-Stats })
$btnSelNone.Add_Click({    foreach ($d in $script:DisplayColl) { $d.Selected=$false }; Update-Stats })
$btnSelActive.Add_Click({  foreach ($d in $script:DisplayColl) { $d.Selected=($d.HAState -eq 'active')  }; Update-Stats })
$btnSelPassive.Add_Click({ foreach ($d in $script:DisplayColl) { $d.Selected=($d.HAState -eq 'passive') }; Update-Stats })
$btnSelSingle.Add_Click({  foreach ($d in $script:DisplayColl) { $d.Selected=($d.HAState -eq '')        }; Update-Stats })
$btnSelNeedUpd.Add_Click({ foreach ($d in $script:DisplayColl) { $d.Selected=(-not $d.IsTargetVer)      }; Update-Stats })
$dgDevices.Add_CurrentCellChanged({ Update-Stats })
$btnClearLog.Add_Click({ $txtLog.Text='' })

# ── Check & Download ─────────────────────────────────────────
$btnCheckDl.Add_Click({
    $sel = @($script:DisplayColl | Where-Object Selected)
    if ($sel.Count -eq 0) { Write-Log "No devices selected."; return }
    $ver = $txtVersion.Text.Trim()
    Write-Log "Checking/downloading $ver on $($sel.Count) device(s)..."
    $btnCheckDl.IsEnabled = $false
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('sel',$sel)
    $rs.SessionStateProxy.SetVariable('ver',$ver)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('btnCheckDl',$btnCheckDl)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        foreach ($dev in $sel) {
            try {
                UI { $dev.DownloadStatus = 'Checking...' }
                $r = Invoke-PANOperation -Command ("<request><system><software><check/></software></system></request>&target=" + $dev.Serial)
                if ($r.status -ne 'success') {
                    Log "  $($dev.Hostname) - check failed"
                    UI { $dev.DownloadStatus = 'Check failed' }
                    continue
                }
                $entry = $r.result.'sw-updates'.versions.entry | Where-Object { $_.version -eq $ver }
                if ($entry.downloaded -eq 'yes') {
                    Log "  $($dev.Hostname) - already downloaded"
                    UI { $dev.DownloadStatus = 'Downloaded' }
                } else {
                    UI { $dev.DownloadStatus = 'Downloading...' }
                    $dl = Invoke-PANOperation -Command ("<request><system><software><download><version>$ver</version></download></software></system></request>&target=" + $dev.Serial)
                    if ($dl.status -eq 'success') {
                        $jid = [string]$dl.result.job
                        UI { $dev.DownloadJobId = $jid; $dev.DownloadStatus = "Job $jid" }
                        Log "  $($dev.Hostname) - download job $jid started"
                    } else {
                        Log "  $($dev.Hostname) - download failed"
                        UI { $dev.DownloadStatus = 'DL failed' }
                    }
                }
            } catch {
                Log "  $($dev.Hostname) - $($_.Exception.Message)"
                UI { $dev.DownloadStatus = 'Error' }
            }
        }
        UI { $btnCheckDl.IsEnabled = $true }
        Log "Download requests done."
    })
    [void]$ps.BeginInvoke()
})

# ── Install ──────────────────────────────────────────────────
$btnInstall.Add_Click({
    $sel = @($script:DisplayColl | Where-Object Selected)
    if ($sel.Count -eq 0) { Write-Log "No devices selected."; return }
    $ver = $txtVersion.Text.Trim()
    $confirm = [System.Windows.MessageBox]::Show("Install $ver on $($sel.Count) selected device(s)?","Confirm Install","YesNo","Warning")
    if ($confirm -ne 'Yes') { return }
    Write-Log "Installing $ver on $($sel.Count) device(s)..."
    $btnInstall.IsEnabled = $false
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('sel',$sel)
    $rs.SessionStateProxy.SetVariable('ver',$ver)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('btnInstall',$btnInstall)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        foreach ($dev in $sel) {
            try {
                UI { $dev.InstallStatus = 'Installing...' }
                $r = Invoke-PANOperation -Command ("<request><system><software><install><version>$ver</version></install></software></system></request>&target=" + $dev.Serial)
                if ($r.status -eq 'success') {
                    $jid = [string]$r.result.job
                    UI { $dev.InstallJobId = $jid; $dev.InstallStatus = "Job $jid" }
                    Log "  $($dev.Hostname) - install job $jid started"
                } else {
                    Log "  $($dev.Hostname) - install failed"
                    UI { $dev.InstallStatus = 'Failed' }
                }
            } catch {
                Log "  $($dev.Hostname) - $($_.Exception.Message)"
                UI { $dev.InstallStatus = 'Error' }
            }
        }
        UI { $btnInstall.IsEnabled = $true }
        Log "Install requests sent."
    })
    [void]$ps.BeginInvoke()
})

# ── Check Job Status ─────────────────────────────────────────
$btnCheckJobs.Add_Click({
    $sel = @($script:DisplayColl | Where-Object { $_.Selected -and ($_.DownloadJobId -ne '' -or $_.InstallJobId -ne '') })
    if ($sel.Count -eq 0) { Write-Log "No selected devices with active jobs."; return }
    Write-Log "Checking job status for $($sel.Count) device(s)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('sel',$sel)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        foreach ($dev in $sel) {
            foreach ($type in @('Download','Install')) {
                $jid = if ($type -eq 'Download') { $dev.DownloadJobId } else { $dev.InstallJobId }
                if ($jid -eq '') { continue }
                try {
                    $r = Invoke-PANOperation -Command ("<show><jobs><id>$jid</id></jobs></show>&target=" + $dev.Serial)
                    $status  = [string]$r.result.job.status
                    $pct     = [string]$r.result.job.progress
                    $summary = "$status $pct%".Trim()
                    Log "  $($dev.Hostname) [$type job $jid] -> $summary"
                    UI {
                        if ($type -eq 'Download') { $dev.DownloadStatus = $summary; if ($status -eq 'FIN') { $dev.DownloadJobId='' } }
                        else                       { $dev.InstallStatus  = $summary; if ($status -eq 'FIN') { $dev.InstallJobId=''  } }
                    }
                } catch { Log "  $($dev.Hostname) [$type] - $($_.Exception.Message)" }
            }
        }
        Log "Job status check done."
    })
    [void]$ps.BeginInvoke()
})

# ── Reboot ───────────────────────────────────────────────────
$btnReboot.Add_Click({
    $sel = @($script:DisplayColl | Where-Object Selected)
    if ($sel.Count -eq 0) { Write-Log "No devices selected."; return }
    $nonPassive = @($sel | Where-Object { $_.HAState -ne 'passive' -and $_.HAState -ne '' })
    $msg = "Reboot $($sel.Count) selected device(s)?"
    if ($nonPassive.Count -gt 0) {
        $names = ($nonPassive | ForEach-Object { $_.Hostname }) -join ', '
        $msg += "`n`nWARNING: NOT passive: $names"
    }
    if ([System.Windows.MessageBox]::Show($msg, "Confirm Reboot", "YesNo", "Warning") -ne 'Yes') { return }
    Write-Log "Rebooting $($sel.Count) device(s)..."
    $btnReboot.IsEnabled = $false
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('sel',$sel)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('btnReboot',$btnReboot)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        foreach ($dev in $sel) {
            try {
                $r = Invoke-PANOperation -Command "<request><restart><system/></restart></request>" -Target $dev.Serial
                Log "  $($dev.Hostname) - $($r.result)"
                UI { $dev.PingStatus = 'Rebooting'; $dev.PingLatency = '-' }
            } catch { Log "  $($dev.Hostname) - $($_.Exception.Message)" }
        }
        UI { $btnReboot.IsEnabled = $true; Start-RebootPoller }
        Log "Reboot commands sent. Auto-poller will detect when devices come back UP."
    })
    [void]$ps.BeginInvoke()
})

# ── Fetch Licenses (NEW: matrix per-firewall view) ───────────
function Invoke-LicenseFetch([object[]]$devs) {
    if (-not $devs -or $devs.Count -eq 0) { Write-Log "No devices selected for licenses."; return }
    foreach ($d in $devs) {
        $d.LicWildFire='-'; $d.LicDNS='-'; $d.LicURL='-'; $d.LicIoT='-'
        $d.LicThreat='-';   $d.LicSupport='-'; $d.LicHasAny=$false
    }
    $txtLicStatus.Text = "Fetching..."
    Write-Log "Fetching licenses for $($devs.Count) device(s)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('devs',$devs)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('txtLicStatus',$txtLicStatus)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        function Get-Cell([string]$expires, [string]$expired) {
            if (-not $expires -and -not $expired) { return '-' }
            if ($expired -eq 'yes') { return "EXPIRED ($expires)" }
            if ($expires -eq 'Never' -or $expires -eq '') { return 'Active' }
            return $expires
        }
        # Walk multiple possible response shapes — pan-power unwraps differently per command.
        function Get-LicEntries($resp) {
            if (-not $resp) { return $null }
            $candidates = @(
                $resp.result.licenses.entry,
                $resp.licenses.entry,
                $resp.result.entry,
                $resp.response.result.licenses.entry
            )
            foreach ($c in $candidates) { if ($c) { return $c } }
            return $null
        }
        $ok = 0; $diagDone = $false
        foreach ($dev in $devs) {
            try {
                # Attempt 1: &target= embedded (read pattern from HANDOFF).
                $resp = Invoke-PANOperation -SkipCertificateCheck `
                            -Command ("<show><license><info/></license></show>&target=" + $dev.Serial)
                $entries = Get-LicEntries $resp
                # Attempt 2: -Target parameter (some pan-power versions proxy this differently).
                if (-not $entries) {
                    try {
                        $resp2 = Invoke-PANOperation -SkipCertificateCheck `
                                    -Command "<show><license><info/></license></show>" -Target $dev.Serial
                        $alt = Get-LicEntries $resp2
                        if ($alt) { $entries = $alt; $resp = $resp2 }
                    } catch {}
                }
                # Attempt 3: <info></info> non-self-closing.
                if (-not $entries) {
                    try {
                        $resp3 = Invoke-PANOperation -SkipCertificateCheck `
                                    -Command ("<show><license><info></info></license></show>&target=" + $dev.Serial)
                        $alt = Get-LicEntries $resp3
                        if ($alt) { $entries = $alt; $resp = $resp3 }
                    } catch {}
                }
                if (-not $entries) {
                    # First failure: dump structure so we can see what Panorama actually returned.
                    if (-not $diagDone) {
                        $diagDone = $true
                        Log "  DIAG [$($dev.Hostname)] license response — investigating shape:"
                        try {
                            if ($resp -and $resp.OuterXml) {
                                $xml = [string]$resp.OuterXml
                                Log "    XML(0..600): $($xml.Substring(0, [Math]::Min(600, $xml.Length)))"
                            } else {
                                $t = if ($resp) { $resp.GetType().FullName } else { '<null>' }
                                Log "    type: $t"
                                if ($resp) {
                                    $props = ($resp | Get-Member -MemberType Properties -ErrorAction SilentlyContinue |
                                              Select-Object -ExpandProperty Name) -join ', '
                                    Log "    props: $props"
                                    if ($resp.result) {
                                        $rprops = ($resp.result | Get-Member -MemberType Properties -ErrorAction SilentlyContinue |
                                                   Select-Object -ExpandProperty Name) -join ', '
                                        Log "    result.props: $rprops"
                                    }
                                }
                            }
                        } catch { Log "    diag error: $($_.Exception.Message)" }
                    }
                    Log "  $($dev.Hostname) - no licenses node in response"
                    continue
                }
                $items = if ($entries -is [array]) { $entries } else { @($entries) }
                $cells = @{ WF='-'; DNS='-'; URL='-'; IoT='-'; Threat='-'; Support='-' }
                foreach ($e in $items) {
                    $feat = [string]$e.feature
                    $val  = Get-Cell ([string]$e.expires) ([string]$e.expired)
                    if     ($feat -match '(?i)wildfire')                                { $cells.WF      = $val }
                    elseif ($feat -match '(?i)dns\s*security|dns-security')             { $cells.DNS     = $val }
                    elseif ($feat -match '(?i)url\s*filt|pan-?db')                      { $cells.URL     = $val }
                    elseif ($feat -match '(?i)iot|device\s*insights|advanced\s*device') { $cells.IoT     = $val }
                    elseif ($feat -match '(?i)threat\s*prevention|advanced\s*threat')   { $cells.Threat  = $val }
                    elseif ($feat -match '(?i)support')                                 { $cells.Support = $val }
                }
                UI {
                    $dev.LicWildFire=$cells.WF; $dev.LicDNS=$cells.DNS; $dev.LicURL=$cells.URL
                    $dev.LicIoT=$cells.IoT; $dev.LicThreat=$cells.Threat; $dev.LicSupport=$cells.Support
                    $dev.LicHasAny=$true
                }
                $ok++
                Log "  $($dev.Hostname) - $($items.Count) feature(s)"
            } catch { Log "  $($dev.Hostname) - $($_.Exception.Message)" }
        }
        UI { $txtLicStatus.Text = "Matrix populated for $ok / $($devs.Count) device(s)" }
        Log "Fetch Licenses complete."
    })
    [void]$ps.BeginInvoke()
}
$btnFetchLicenses.Add_Click({ Invoke-LicenseFetch @($script:DisplayColl | Where-Object Selected) })
$btnFetchLicAll.Add_Click({   Invoke-LicenseFetch @($script:DisplayColl) })

# ── Export CSVs ──────────────────────────────────────────────
$btnExportLicCSV.Add_Click({
    $rows = @($script:DisplayColl | Where-Object { $_.LicHasAny })
    if ($rows.Count -eq 0) { Write-Log "No license data - click Fetch Licenses first."; return }
    $sfd = [System.Windows.Forms.SaveFileDialog]::new(); $sfd.Filter="CSV|*.csv|All|*.*"
    $sfd.FileName = "license_matrix_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($sfd.ShowDialog() -ne 'OK') { return }
    try {
        $rows | Select-Object Hostname,Model,Serial,LicWildFire,LicDNS,LicURL,LicIoT,LicThreat,LicSupport |
            Export-Csv -Path $sfd.FileName -NoTypeInformation -Encoding UTF8
        Write-Log "Exported license matrix for $($rows.Count) device(s) to $($sfd.FileName)"
    } catch { Write-Log "Export failed: $($_.Exception.Message)" }
})

# ── Ping (runspace-based, simple OLD pattern) ────────────────
function Start-PingLoop {
    if ($script:PingCtrl.Running) { return }
    $script:PingCtrl.Stop    = $false
    $script:PingCtrl.Running = $true
    UI { $btnPingStart.IsEnabled = $false; $btnPingStop.IsEnabled = $true }
    Write-Log "▶ Ping loop started (every 5 s)."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('ctrl',        $script:PingCtrl)
    $rs.SessionStateProxy.SetVariable('DisplayColl', $script:DisplayColl)
    $rs.SessionStateProxy.SetVariable('Window',      $Window)
    $rs.SessionStateProxy.SetVariable('btnPingStart',$btnPingStart)
    $rs.SessionStateProxy.SetVariable('btnPingStop', $btnPingStop)
    $rs.SessionStateProxy.SetVariable('writeLogFn',  ${function:Write-Log})
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        function Log($m) { & $writeLogFn $m }
        $cycle = 0
        try {
            while (-not $ctrl.Stop) {
                $cycle++
                try {
                    # SNAPSHOT — copy device refs on the UI thread into a plain list so we
                    # never enumerate the ObservableCollection off-thread. @() forces a copy
                    # of the collection in case Apply-Filter etc. mutates it mid-iteration.
                    $snapshot = New-Object 'System.Collections.Generic.List[object]'
                    $Window.Dispatcher.Invoke([action]{
                        foreach ($d in @($DisplayColl)) {
                            if ($d.IPAddress) { $snapshot.Add($d) }
                        }
                    }, 'Normal')
                    if ($cycle -eq 1) { Log "  Ping cycle 1 - pinging $($snapshot.Count) device(s)." }

                    if ($snapshot.Count -gt 0 -and -not $ctrl.Stop) {
                        # Kick off all pings in parallel.
                        $jobs = New-Object 'System.Collections.Generic.List[object]'
                        foreach ($dev in $snapshot) {
                            $p = $null
                            try {
                                $p = [System.Net.NetworkInformation.Ping]::new()
                                $t = $p.SendPingAsync([string]$dev.IPAddress, 1000)
                                $jobs.Add([PSCustomObject]@{ Dev=$dev; Ping=$p; Task=$t })
                            } catch {
                                try { if ($p) { $p.Dispose() } } catch {}
                            }
                        }
                        # Collect results into a list — no UI calls inside this loop, so
                        # the foreach variable doesn't race with any deferred dispatch.
                        $results = New-Object 'System.Collections.Generic.List[object]'
                        foreach ($job in $jobs) {
                            if ($ctrl.Stop) { break }
                            $s = '? ERR'; $l = '-'
                            try {
                                if ($job.Task.Wait(1500)) {
                                    $r = $job.Task.Result
                                    if ($r -and $r.Status -eq 'Success') {
                                        $s = '● UP';   $l = "$($r.RoundtripTime) ms"
                                    } else {
                                        $s = '○ DOWN'; $l = '-'
                                    }
                                }
                            } catch {}
                            try { $job.Ping.Dispose() } catch {}
                            $results.Add([PSCustomObject]@{ Dev=$job.Dev; Status=$s; Latency=$l })
                        }
                        # Push every update in ONE dispatcher call — fast, atomic on the UI
                        # thread, and avoids the BeginInvoke-closure race (where $dev/$ss/$ll
                        # got reassigned by the next loop iteration before the deferred
                        # scriptblock ran).
                        if ($results.Count -gt 0 -and -not $ctrl.Stop) {
                            $Window.Dispatcher.Invoke([action]{
                                foreach ($r in $results) {
                                    $r.Dev.PingStatus  = $r.Status
                                    $r.Dev.PingLatency = $r.Latency
                                }
                            }, 'Normal')
                        }
                    }
                } catch {
                    Log "  ✘ Ping cycle $cycle error: $($_.Exception.GetType().Name): $($_.Exception.Message)"
                }
                $w=0; while ($w -lt 5000 -and -not $ctrl.Stop) { [System.Threading.Thread]::Sleep(200); $w+=200 }
            }
        } catch {
            Log "✘ Ping loop CRASHED: $($_.Exception.GetType().Name): $($_.Exception.Message)"
            if ($_.ScriptStackTrace) {
                $frames = ($_.ScriptStackTrace -split "`n" | Select-Object -First 3) -join ' | '
                Log "  at: $frames"
            }
        } finally {
            $ctrl.Running = $false
            try {
                $Window.Dispatcher.Invoke([action]{
                    $btnPingStart.IsEnabled = $true
                    $btnPingStop.IsEnabled  = $false
                }, 'Normal')
            } catch {}
            Log "⏹ Ping loop stopped (after $cycle cycle(s))."
        }
    })
    $script:PingPS = $ps; $script:PingRS = $rs
    [void]$ps.BeginInvoke()
}
$btnPingStart.Add_Click({ Start-PingLoop })
$btnPingStop.Add_Click({
    $script:PingCtrl.Stop = $true
    $btnPingStop.IsEnabled = $false
})

# ── Reboot Poller (auto-detects devices coming back UP) ─────────────────────
# Pings every device whose PingStatus is 'Rebooting' every 15 s. When a ping
# succeeds, sets PingStatus='● UP' and PingLatency=<rtt>. Stops automatically
# when no devices are in Rebooting state.
function Start-RebootPoller {
    if ($script:RebootPollCtrl.Running) {
        Write-Log "Reboot poller already running."
        return
    }
    $script:RebootPollCtrl.Stop    = $false
    $script:RebootPollCtrl.Running = $true
    Write-Log "Reboot poller started (15 s interval)."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('ctrl',       $script:RebootPollCtrl)
    $rs.SessionStateProxy.SetVariable('AllDevices', $script:AllDevices)
    $rs.SessionStateProxy.SetVariable('Window',     $Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn', ${function:Write-Log})
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        try {
            while (-not $ctrl.Stop) {
                # Snapshot the set of devices currently in 'Rebooting' state via the UI thread.
                $rebooting = [System.Collections.Generic.List[object]]::new()
                UI {
                    foreach ($d in $AllDevices) {
                        if ($d.PingStatus -eq 'Rebooting' -and $d.IPAddress) {
                            $rebooting.Add([PSCustomObject]@{ Dev=$d; IP=[string]$d.IPAddress; Host=[string]$d.Hostname })
                        }
                    }
                }
                if ($rebooting.Count -eq 0) {
                    Log "Reboot poller: no devices rebooting — exiting."
                    break
                }
                # Ping each rebooting device
                foreach ($r in $rebooting) {
                    if ($ctrl.Stop) { break }
                    try {
                        $p = [System.Net.NetworkInformation.Ping]::new()
                        $reply = $p.Send($r.IP, 1500)
                        $p.Dispose()
                        if ($reply -and $reply.Status -eq 'Success') {
                            $rtt = "$($reply.RoundtripTime) ms"
                            $dev = $r.Dev
                            UI { $dev.PingStatus = '● UP'; $dev.PingLatency = $rtt }
                            Log "  ✔ $($r.Host) back UP ($rtt)"
                        }
                    } catch {}
                }
                # Wait 15 s but stay responsive to Stop
                $w = 0; while ($w -lt 15000 -and -not $ctrl.Stop) { [System.Threading.Thread]::Sleep(500); $w += 500 }
            }
        } catch {
            Log "Reboot poller error: $($_.Exception.Message)"
        } finally {
            $ctrl.Running = $false
            Log "Reboot poller stopped."
        }
    })
    [void]$ps.BeginInvoke()
}

# ════════════════════════════════════════════════════════════
#  NEW TOOLS — User-ID / ARP / IPsec / Routes / Locks / EDLs
# ════════════════════════════════════════════════════════════
# Each fetch follows the same shape: validate selection, set status,
# spin up a runspace, sequential foreach over devices, parse response,
# push rows into the tab's ObservableCollection via Dispatcher.Invoke.
# ARP and Routes maintain a backing $script:ColXAll list so the filter
# textbox can re-project visible rows without re-querying.

function Export-CollToCSV {
    param([System.Collections.IEnumerable]$Rows, [string]$DefaultName)
    $rows = @($Rows)
    if ($rows.Count -eq 0) { Write-Log "Nothing to export."; return }
    $sfd = [System.Windows.Forms.SaveFileDialog]::new()
    $sfd.Filter   = "CSV|*.csv|All|*.*"
    $sfd.FileName = "${DefaultName}_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($sfd.ShowDialog() -ne 'OK') { return }
    try {
        $rows | Export-Csv -Path $sfd.FileName -NoTypeInformation -Encoding UTF8
        Write-Log "Exported $($rows.Count) row(s) to $($sfd.FileName)"
    } catch { Write-Log "Export failed: $($_.Exception.Message)" }
}

# ── User-ID Health ───────────────────────────────────────────
function Invoke-UserIDFetch([object[]]$devs) {
    if (-not $devs -or $devs.Count -eq 0) { Write-Log "No devices selected for User-ID check."; return }
    $txtUserIDStatus.Text = "Fetching..."
    Write-Log "Checking User-ID on $($devs.Count) device(s)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('devs',$devs)
    $rs.SessionStateProxy.SetVariable('coll',$script:ColUserID)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtUserIDStatus)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        UI { $coll.Clear() }
        $ok = 0
        foreach ($dev in $devs) {
            try {
                $row = [PSCustomObject]@{
                    Hostname       = $dev.Hostname
                    Serial         = $dev.Serial
                    IPMappings     = '?'
                    AgentTotal     = '?'
                    AgentConnected = '?'
                    GroupCount     = '?'
                    Issues         = ''
                }
                try {
                    $ipMap = Invoke-PANOperation -SkipCertificateCheck `
                                -Command "<show><user><ip-user-mapping><all></all></ip-user-mapping></user></show>" `
                                -Target $dev.Serial
                    $row.IPMappings = [string]$ipMap.result.count
                } catch { $row.IPMappings='err'; $row.Issues += "ip-map err; " }
                try {
                    $agent = Invoke-PANOperation -SkipCertificateCheck `
                                -Command "<show><user><user-id-agent><statistics/></user-id-agent></user></show>" `
                                -Target $dev.Serial
                    $entries = @($agent.result.entry)
                    $row.AgentTotal     = $entries.Count
                    $row.AgentConnected = @($entries | Where-Object { $_.Connected -eq 'yes' }).Count
                    if ($row.AgentTotal -eq 0) { $row.Issues += "no agents; " }
                } catch { $row.AgentTotal='err'; $row.Issues += "agent err; " }
                try {
                    $grp = Invoke-PANOperation -SkipCertificateCheck `
                                -Command "<show><user><group-mapping><state>all</state></group-mapping></user></show>" `
                                -Target $dev.Serial
                    $cdata = [string]$grp.result.'#cdata-section'
                    if ($cdata) {
                        $m = [regex]::Match($cdata, 'Number of Groups:\s*(\d+)')
                        if ($m.Success) { $row.GroupCount = [int]$m.Groups[1].Value }
                    }
                } catch { $row.GroupCount='err'; $row.Issues += "group err; " }
                UI { $coll.Add($row) }
                $ok++
                Log "  $($dev.Hostname) - IP:$($row.IPMappings) Agt:$($row.AgentConnected)/$($row.AgentTotal) Grp:$($row.GroupCount)"
            } catch { Log "  $($dev.Hostname) - $($_.Exception.Message)" }
        }
        UI { $txtStatus.Text = "Done - $ok / $($devs.Count) device(s)" }
        Log "User-ID check complete."
    })
    [void]$ps.BeginInvoke()
}
$btnFetchUserID.Add_Click({    Invoke-UserIDFetch @($script:DisplayColl | Where-Object Selected) })
$btnFetchUserIDAll.Add_Click({ Invoke-UserIDFetch @($script:DisplayColl) })
$btnExportUserID.Add_Click({   Export-CollToCSV $script:ColUserID 'userid' })

# ── ARP ──────────────────────────────────────────────────────
function Update-ARPFilter {
    $f = $txtARPFilter.Text.Trim()
    $script:ColARP.Clear()
    if ($f -eq '') {
        foreach ($r in $script:ColARPAll) { $script:ColARP.Add($r) }
    } else {
        foreach ($r in $script:ColARPAll) {
            try { if (($r.IP -match $f) -or ($r.MAC -match $f)) { $script:ColARP.Add($r) } } catch {}
        }
    }
    $txtARPStatus.Text = "Showing $($script:ColARP.Count) of $($script:ColARPAll.Count) entries"
}
function Invoke-ARPFetch([object[]]$devs) {
    if (-not $devs -or $devs.Count -eq 0) { Write-Log "No devices selected for ARP."; return }
    $txtARPStatus.Text = "Fetching..."
    Write-Log "Fetching ARP from $($devs.Count) device(s)..."
    $script:ColARPAll.Clear(); $script:ColARP.Clear()
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('devs',$devs)
    $rs.SessionStateProxy.SetVariable('allList',$script:ColARPAll)
    $rs.SessionStateProxy.SetVariable('coll',$script:ColARP)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtARPStatus)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        $total = 0
        foreach ($dev in $devs) {
            try {
                $resp = Invoke-PANOperation -SkipCertificateCheck `
                            -Command "<show><arp><entry name='all'/></arp></show>" `
                            -Target $dev.Serial
                if ($resp.status -ne 'success') { Log "  $($dev.Hostname) - status=$($resp.status)"; continue }
                $entries = @($resp.result.entries.entry)
                $rows = New-Object 'System.Collections.Generic.List[object]'
                foreach ($e in $entries) {
                    $rows.Add([PSCustomObject]@{
                        Hostname  = $dev.Hostname
                        Interface = [string]$e.interface
                        IP        = [string]$e.ip
                        MAC       = [string]$e.mac
                        Port      = [string]$e.port
                        Status    = [string]$e.status
                        TTL       = [string]$e.ttl
                    })
                }
                UI {
                    foreach ($r in $rows) { $allList.Add($r); $coll.Add($r) }
                    $txtStatus.Text = "Fetched $($total + $rows.Count) entries..."
                }
                $total += $rows.Count
                Log "  $($dev.Hostname) - $($rows.Count) ARP entries"
            } catch { Log "  $($dev.Hostname) - $($_.Exception.Message)" }
        }
        UI { $txtStatus.Text = "Done - $total entries from $($devs.Count) device(s)" }
        Log "ARP fetch complete: $total entries."
    })
    [void]$ps.BeginInvoke()
}
$btnFetchARP.Add_Click({         Invoke-ARPFetch @($script:DisplayColl | Where-Object Selected) })
$btnFetchARPAll.Add_Click({      Invoke-ARPFetch @($script:DisplayColl) })
$btnExportARP.Add_Click({        Export-CollToCSV $script:ColARPAll 'arp' })
$txtARPFilter.Add_TextChanged({  Update-ARPFilter })
$btnARPClearFilter.Add_Click({   $txtARPFilter.Text = '' })

# ── IPsec ────────────────────────────────────────────────────
function Invoke-IPsecFetch([object[]]$devs) {
    if (-not $devs -or $devs.Count -eq 0) { Write-Log "No devices selected for IPsec."; return }
    $txtIPsecStatus.Text = "Fetching..."
    Write-Log "Fetching IPsec SAs from $($devs.Count) device(s)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('devs',$devs)
    $rs.SessionStateProxy.SetVariable('coll',$script:ColIPsec)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtIPsecStatus)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        UI { $coll.Clear() }
        $total = 0
        foreach ($dev in $devs) {
            try {
                $resp = Invoke-PANOperation -SkipCertificateCheck `
                            -Command "<show><vpn><ipsec-sa/></vpn></show>" `
                            -Target $dev.Serial
                if ($resp.status -ne 'success') { Log "  $($dev.Hostname) - status=$($resp.status)"; continue }
                $entries = @($resp.result.entries.entry)
                $rows = New-Object 'System.Collections.Generic.List[object]'
                foreach ($e in $entries) {
                    # Field names vary by PAN-OS version; pull whatever's present.
                    $rows.Add([PSCustomObject]@{
                        Hostname  = $dev.Hostname
                        Name      = [string]$e.name
                        Peer      = [string]$e.peerip
                        GwName    = [string]$e.gwid
                        State     = [string]$e.state
                        Algorithm = "$([string]$e.algo) $([string]$e.hash)".Trim()
                    })
                }
                if ($rows.Count -eq 0 -and $entries.Count -gt 0) {
                    # Fallback - just use raw entry as a row
                    foreach ($e in $entries) {
                        $rows.Add([PSCustomObject]@{
                            Hostname=$dev.Hostname; Name=[string]$e.Name
                            Peer=[string]$e.Remote; GwName=''; State=''; Algorithm=''
                        })
                    }
                }
                UI { foreach ($r in $rows) { $coll.Add($r) } }
                $total += $rows.Count
                Log "  $($dev.Hostname) - $($rows.Count) IPsec SA(s)"
            } catch { Log "  $($dev.Hostname) - $($_.Exception.Message)" }
        }
        UI { $txtStatus.Text = "Done - $total SA(s) from $($devs.Count) device(s)" }
        Log "IPsec fetch complete: $total SA(s)."
    })
    [void]$ps.BeginInvoke()
}
$btnFetchIPsec.Add_Click({    Invoke-IPsecFetch @($script:DisplayColl | Where-Object Selected) })
$btnFetchIPsecAll.Add_Click({ Invoke-IPsecFetch @($script:DisplayColl) })
$btnExportIPsec.Add_Click({   Export-CollToCSV $script:ColIPsec 'ipsec' })

# ── Routes ───────────────────────────────────────────────────
function Update-RoutesFilter {
    $f = $txtRouteFilter.Text.Trim()
    $script:ColRoutes.Clear()
    if ($f -eq '') {
        foreach ($r in $script:ColRoutesAll) { $script:ColRoutes.Add($r) }
    } else {
        foreach ($r in $script:ColRoutesAll) {
            try { if ($r.Destination -match $f) { $script:ColRoutes.Add($r) } } catch {}
        }
    }
    $txtRoutesStatus.Text = "Showing $($script:ColRoutes.Count) of $($script:ColRoutesAll.Count) routes"
}
function Invoke-RoutesFetch([object[]]$devs) {
    if (-not $devs -or $devs.Count -eq 0) { Write-Log "No devices selected for routes."; return }
    $txtRoutesStatus.Text = "Fetching..."
    Write-Log "Fetching routes from $($devs.Count) device(s)..."
    $script:ColRoutesAll.Clear(); $script:ColRoutes.Clear()
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('devs',$devs)
    $rs.SessionStateProxy.SetVariable('allList',$script:ColRoutesAll)
    $rs.SessionStateProxy.SetVariable('coll',$script:ColRoutes)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtRoutesStatus)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        $total = 0
        foreach ($dev in $devs) {
            try {
                $resp = Invoke-PANOperation -SkipCertificateCheck `
                            -Command "<show><routing><route/></routing></show>" `
                            -Target $dev.Serial
                if ($resp.status -ne 'success') { Log "  $($dev.Hostname) - status=$($resp.status)"; continue }
                $entries = @($resp.result.entry)
                $rows = New-Object 'System.Collections.Generic.List[object]'
                foreach ($e in $entries) {
                    $rows.Add([PSCustomObject]@{
                        Hostname    = $dev.Hostname
                        VR          = [string]$e.'virtual-router'
                        Destination = [string]$e.destination
                        NextHop     = [string]$e.nexthop
                        Metric      = [string]$e.metric
                        Flags       = [string]$e.flags
                        Age         = [string]$e.age
                        Interface   = [string]$e.interface
                    })
                }
                UI {
                    foreach ($r in $rows) { $allList.Add($r); $coll.Add($r) }
                    $txtStatus.Text = "Fetched $($total + $rows.Count) routes..."
                }
                $total += $rows.Count
                Log "  $($dev.Hostname) - $($rows.Count) route(s)"
            } catch { Log "  $($dev.Hostname) - $($_.Exception.Message)" }
        }
        UI { $txtStatus.Text = "Done - $total routes from $($devs.Count) device(s)" }
        Log "Routes fetch complete: $total routes."
    })
    [void]$ps.BeginInvoke()
}
$btnFetchRoutes.Add_Click({       Invoke-RoutesFetch @($script:DisplayColl | Where-Object Selected) })
$btnFetchRoutesAll.Add_Click({    Invoke-RoutesFetch @($script:DisplayColl) })
$btnExportRoutes.Add_Click({      Export-CollToCSV $script:ColRoutesAll 'routes' })
$txtRouteFilter.Add_TextChanged({ Update-RoutesFilter })
$btnRouteClearFilter.Add_Click({  $txtRouteFilter.Text = '' })

# ── Config Locks ─────────────────────────────────────────────
function Invoke-LocksFetch([object[]]$devs) {
    if (-not $devs -or $devs.Count -eq 0) { Write-Log "No devices selected for locks."; return }
    $txtLocksStatus.Text = "Fetching..."
    Write-Log "Checking commit-locks on $($devs.Count) device(s)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('devs',$devs)
    $rs.SessionStateProxy.SetVariable('coll',$script:ColLocks)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtLocksStatus)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        UI { $coll.Clear() }
        $totalLocks = 0; $locked = 0
        foreach ($dev in $devs) {
            try {
                $resp = Invoke-PANOperation -SkipCertificateCheck `
                            -Command "<show><commit-locks><vsys>all</vsys></commit-locks></show>" `
                            -Target $dev.Serial
                $entries = @($resp.result.'commit-locks'.entry)
                if ($entries.Count -eq 0) { continue }
                $locked++
                $rows = New-Object 'System.Collections.Generic.List[object]'
                foreach ($e in $entries) {
                    $rows.Add([PSCustomObject]@{
                        Hostname = $dev.Hostname
                        LockType = 'commit'
                        Admin    = [string]$e.name
                        Vsys     = [string]$e.vsys
                        Created  = [string]$e.'loc-time'
                        Comment  = [string]$e.comment
                    })
                }
                UI { foreach ($r in $rows) { $coll.Add($r) } }
                $totalLocks += $rows.Count
                Log "  $($dev.Hostname) - $($rows.Count) lock(s)"
            } catch { Log "  $($dev.Hostname) - $($_.Exception.Message)" }
        }
        UI { $txtStatus.Text = "Done - $totalLocks lock(s) on $locked / $($devs.Count) device(s)" }
        Log "Lock check complete: $totalLocks lock(s) on $locked device(s)."
    })
    [void]$ps.BeginInvoke()
}
function Invoke-LocksRemove([object[]]$devs) {
    if (-not $devs -or $devs.Count -eq 0) { Write-Log "No devices selected for lock removal."; return }
    $msg = "Remove ALL commit-locks on $($devs.Count) selected device(s)?`n`nThis reverts any uncommitted config changes on the device side."
    if ([System.Windows.MessageBox]::Show($msg, "Confirm Remove Locks", "YesNo", "Warning") -ne 'Yes') { return }
    $txtLocksStatus.Text = "Removing..."
    Write-Log "Removing locks on $($devs.Count) device(s)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('devs',$devs)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtLocksStatus)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        $cleared = 0
        foreach ($dev in $devs) {
            try {
                $show = Invoke-PANOperation -SkipCertificateCheck `
                            -Command "<show><commit-locks><vsys>all</vsys></commit-locks></show>" `
                            -Target $dev.Serial
                $entries = @($show.result.'commit-locks'.entry)
                if ($entries.Count -eq 0) {
                    Log "  $($dev.Hostname) - no locks"
                    continue
                }
                # Revert any pending changes, then unlock each admin holding a lock.
                try { [void](Invoke-PANOperation -SkipCertificateCheck -Command "<revert><config></config></revert>" -Target $dev.Serial) } catch {}
                foreach ($e in $entries) {
                    $admin = [string]$e.name
                    if (-not $admin) { continue }
                    try {
                        $r = Invoke-PANOperation -SkipCertificateCheck `
                                -Command ("<request><commit-lock><remove><admin>" + $admin + "</admin></remove></commit-lock></request>") `
                                -Target $dev.Serial
                        Log "  $($dev.Hostname) - removed lock for $admin -> $($r.status)"
                        $cleared++
                    } catch { Log "  $($dev.Hostname) - error removing $admin lock: $($_.Exception.Message)" }
                }
            } catch { Log "  $($dev.Hostname) - $($_.Exception.Message)" }
        }
        UI { $txtStatus.Text = "Removed $cleared lock(s)." }
        Log "Lock removal complete: $cleared lock(s) cleared."
    })
    [void]$ps.BeginInvoke()
}
$btnFetchLocks.Add_Click({    Invoke-LocksFetch @($script:DisplayColl | Where-Object Selected) })
$btnFetchLocksAll.Add_Click({ Invoke-LocksFetch @($script:DisplayColl) })
$btnRemoveLocks.Add_Click({   Invoke-LocksRemove @($script:DisplayColl | Where-Object Selected) })
$btnExportLocks.Add_Click({   Export-CollToCSV $script:ColLocks 'locks' })

# ── EDLs ─────────────────────────────────────────────────────
function Invoke-EDLFetch {
    $txtEDLStatus.Text = "Loading EDL list..."
    Write-Log "Loading shared EDLs from Panorama..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('coll',$script:ColEDLs)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtEDLStatus)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        UI { $coll.Clear() }
        try {
            $resp = Get-PANConfig -XPath '/config/shared/external-list' -SkipCertificateCheck
            $entries = @($resp.result.'external-list'.entry)
            if ($entries.Count -eq 0) {
                Log "No shared EDLs found."
                UI { $txtStatus.Text = "No shared EDLs found." }
                return
            }
            $rows = New-Object 'System.Collections.Generic.List[object]'
            foreach ($e in $entries) {
                $kind = if ($e.type.ip) { 'ip' } elseif ($e.type.url) { 'url' } elseif ($e.type.domain) { 'domain' } else { 'unknown' }
                $url  = ''
                if     ($kind -eq 'ip')     { $url = [string]$e.type.ip.url }
                elseif ($kind -eq 'url')    { $url = [string]$e.type.url.url }
                elseif ($kind -eq 'domain') { $url = [string]$e.type.domain.url }
                $edl = [EDLEntry]::new()
                $edl.Selected = $false
                $edl.Name = [string]$e.name
                $edl.Type = $kind
                $edl.Url  = $url
                $edl.Description = [string]$e.description
                $rows.Add($edl)
            }
            UI { foreach ($r in $rows) { $coll.Add($r) } }
            UI { $txtStatus.Text = "Loaded $($rows.Count) EDL(s)." }
            Log "Loaded $($rows.Count) shared EDL(s)."
        } catch {
            Log "EDL load failed: $($_.Exception.Message)"
            UI { $txtStatus.Text = "Load failed." }
        }
    })
    [void]$ps.BeginInvoke()
}
function Invoke-EDLRefresh {
    $checked = @($script:ColEDLs | Where-Object Selected)
    $devs    = @($script:DisplayColl | Where-Object Selected)
    if ($checked.Count -eq 0) { Write-Log "No EDLs checked."; return }
    if ($devs.Count    -eq 0) { Write-Log "No devices selected on Devices tab."; return }
    $msg = "Refresh $($checked.Count) EDL(s) on $($devs.Count) device(s)? ($($checked.Count * $devs.Count) total requests)"
    if ([System.Windows.MessageBox]::Show($msg,"Confirm EDL Refresh","YesNo","Question") -ne 'Yes') { return }
    $txtEDLStatus.Text = "Refreshing..."
    Write-Log "Refreshing $($checked.Count) EDL(s) on $($devs.Count) device(s)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('edls',$checked)
    $rs.SessionStateProxy.SetVariable('devs',$devs)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtEDLStatus)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        $ok = 0; $fail = 0
        foreach ($edl in $edls) {
            $kind = $edl.Type
            if ($kind -eq 'unknown') { Log "  Skipping '$($edl.Name)' - unknown type"; continue }
            $cmd  = "<request><system><external-list><refresh><type><$kind><name>$($edl.Name)</name></$kind></type></refresh></external-list></system></request>"
            foreach ($dev in $devs) {
                try {
                    $r = Invoke-PANOperation -SkipCertificateCheck -Command $cmd -Target $dev.Serial
                    if ($r.status -eq 'success') {
                        $ok++
                        Log "  $($dev.Hostname) <- $($edl.Name) -> OK"
                    } else {
                        $fail++
                        Log "  $($dev.Hostname) <- $($edl.Name) -> $($r.status) $($r.msg)"
                    }
                } catch { $fail++; Log "  $($dev.Hostname) <- $($edl.Name) - $($_.Exception.Message)" }
            }
        }
        UI { $txtStatus.Text = "Done - OK:$ok Fail:$fail" }
        Log "EDL refresh complete: OK=$ok Fail=$fail"
    })
    [void]$ps.BeginInvoke()
}
$btnFetchEDLs.Add_Click({   Invoke-EDLFetch })
$btnRefreshEDLs.Add_Click({ Invoke-EDLRefresh })
$btnSelAllEDLs.Add_Click({  foreach ($e in $script:ColEDLs) { $e.Selected = $true  } })
$btnSelNoneEDLs.Add_Click({ foreach ($e in $script:ColEDLs) { $e.Selected = $false } })

# ── Shutdown ─────────────────────────────────────────────────
$Window.Add_Closing({
    $script:PingCtrl.Stop       = $true
    $script:RebootPollCtrl.Stop = $true
})

Write-Log "Palo Alto Firewall Manager ready. Enter Panorama IP and click Connect."
[void]$Window.ShowDialog()
