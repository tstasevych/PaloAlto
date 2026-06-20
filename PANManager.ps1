#Requires -Version 5.1
# ============================================================
#  Palo Alto Firewall Manager – WPF GUI
#  Requires:  pan-power module  (Install-Module 'pan-power' -Scope CurrentUser)
#  Run with:  PowerShell.exe -STA -File PANManager.ps1
#
#  Based on scripts by Steve Borba:
#    https://github.com/sjborbajr/PaloAltoNetworks/
#  Credit and thanks to Steve Borba for the pan-power module and the
#  Install-Software / User-ID-check / ARP / IPsec / Routes / commit-lock /
#  EDL refresh scripts that this GUI extends and unifies into one tool.
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
Add-Type -AssemblyName System.Web

# ── TLS cert-bypass helper (compiled, NOT a PS scriptblock) ──
# The license REST calls need to accept self-signed PAN-OS mgmt certs.
# CRITICAL: ServerCertificateValidationCallback must be a compiled .NET method,
# NOT a PowerShell scriptblock. A scriptblock callback persists process-wide on
# ServicePointManager AFTER its originating runspace is disposed; .NET then
# tries to invoke it on a thread with no runspace, throws PSInvalidOperationException
# "There is no Runspace available to run scripts in this thread", returns false,
# and EVERY subsequent TLS handshake in the process (including pan-power's)
# fails with "underlying connection was closed: An unexpected error occurred on
# a send". This is how an earlier revision of this script silently broke every
# tab after License was clicked. Don't reintroduce a scriptblock callback.
if (-not ('SSLAcceptAll' -as [type])) {
    Add-Type -TypeDefinition @'
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public class SSLAcceptAll {
    public static bool Validate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors) {
        return true;
    }
    public static RemoteCertificateValidationCallback Callback {
        get { return new RemoteCertificateValidationCallback(Validate); }
    }
}
'@ -ErrorAction SilentlyContinue
}

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
              <Button x:Name="btnResyncGroups"   Content="⟳ Resync Groups"    Style="{StaticResource BtnAmber}" IsEnabled="False" Padding="10,4" Margin="10,0,0,0" ToolTip="debug user-id refresh group-mapping all (on selected firewalls)"/>
              <Button x:Name="btnResyncCIE"      Content="⟳ Resync CIE"       Style="{StaticResource BtnAmber}" IsEnabled="False" Padding="10,4" Margin="4,0" ToolTip="debug user-id cloud-identity-engine resync (on selected firewalls)"/>
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
              <Button x:Name="btnClearARP"    Content="✕ Clear ARP (Selected FWs)" Style="{StaticResource BtnRed}" IsEnabled="False" Padding="10,4" Margin="10,0,0,0" ToolTip="clear arp all (on each selected firewall)"/>
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
              <Button x:Name="btnClearIPsec"    Content="✕ Clear Selected Tunnels" Style="{StaticResource BtnRed}"   IsEnabled="False" Padding="10,4" Margin="10,0,0,0" ToolTip="Select one or more rows in the grid below, then click to clear those IPsec SAs"/>
              <TextBlock x:Name="txtIPsecStatus" Text="" Foreground="#8888AA" FontSize="11" VerticalAlignment="Center" Margin="14,0,0,0"/>
            </WrapPanel>
          </Border>
          <DataGrid x:Name="dgIPsec" Grid.Row="1" AutoGenerateColumns="False" CanUserAddRows="False" IsReadOnly="True" SelectionMode="Extended" SelectionUnit="FullRow">
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
      <TabItem Header="🌐 Interfaces">
        <Grid Background="#1A1A2C">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <Border Grid.Row="0" Background="#0F0F1E" Padding="8,6" Margin="0,0,0,2">
            <WrapPanel Orientation="Horizontal">
              <Button x:Name="btnFetchIf"    Content="↻ Fetch Interface IPs (Selected)" Style="{StaticResource BtnGreen}" IsEnabled="False" Padding="12,4"/>
              <Button x:Name="btnFetchIfAll" Content="↻ All"                            Style="{StaticResource Btn}"      IsEnabled="False" Padding="10,4" Margin="4,0"/>
              <Button x:Name="btnExportIf"   Content="📥 Export CSV"                     Style="{StaticResource BtnGray}"  Padding="10,4"/>
              <Label Content="Scope:" Style="{StaticResource Lbl}" Margin="10,0,0,0"/>
              <ComboBox x:Name="cbIfScope" Width="90" VerticalAlignment="Center" ToolTip="Public vs private (10/8, 172.16-31, 192.168/16, 169.254/16)">
                <ComboBoxItem Content="(All)" IsSelected="True"/>
                <ComboBoxItem Content="Public"/>
                <ComboBoxItem Content="Private"/>
              </ComboBox>
              <Label Content="Zone:" Style="{StaticResource Lbl}" Margin="8,0,0,0"/>
              <TextBox x:Name="txtIfZone" Width="110" Style="{StaticResource TBox}" ToolTip="Regex matched against zone"/>
              <Label Content="Region:" Style="{StaticResource Lbl}" Margin="8,0,0,0"/>
              <TextBox x:Name="txtIfRegion" Width="70" Style="{StaticResource TBox}" ToolTip="Regex matched against region (US/EU/AU/NZ/UK/CH/MFG/SHP, derived from hostname)"/>
              <Label Content="Iface/IP:" Style="{StaticResource Lbl}" Margin="8,0,0,0"/>
              <TextBox x:Name="txtIfFilter" Width="150" Style="{StaticResource TBox}" ToolTip="Regex matched against Interface and IP"/>
              <Label Content="ARPs:" Style="{StaticResource Lbl}" Margin="8,0,0,0"/>
              <ComboBox x:Name="cbIfArp" Width="120" VerticalAlignment="Center" ToolTip="Valid ARP = another device with a real MAC on the interface (excludes the interface's own IP and incomplete entries)">
                <ComboBoxItem Content="(All)" IsSelected="True"/>
                <ComboBoxItem Content="Has valid ARPs"/>
                <ComboBoxItem Content="No valid ARPs"/>
              </ComboBox>
              <Button x:Name="btnIfClearFilter" Content="✕" Style="{StaticResource BtnGray}" Padding="6,4"/>
              <TextBlock x:Name="txtIfStatus" Text="" Foreground="#8888AA" FontSize="11" VerticalAlignment="Center" Margin="14,0,0,0"/>
            </WrapPanel>
          </Border>
          <DataGrid x:Name="dgIf" Grid.Row="1" AutoGenerateColumns="False" CanUserAddRows="False" IsReadOnly="True">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Hostname"  Binding="{Binding Hostname}"  Width="170"/>
              <DataGridTextColumn Header="Region"    Binding="{Binding Region}"    Width="70"/>
              <DataGridTextColumn Header="Interface" Binding="{Binding Interface}" Width="130"/>
              <DataGridTextColumn Header="Zone"      Binding="{Binding Zone}"      Width="120"/>
              <DataGridTextColumn Header="IP"        Binding="{Binding IP}"        Width="150"/>
              <DataGridTextColumn Header="Scope"     Binding="{Binding Scope}"     Width="80"/>
              <DataGridTextColumn Header="ARPs"      Binding="{Binding ARPCount}"  Width="60"/>
              <DataGridTextColumn Header="VR"        Binding="{Binding VR}"        Width="110"/>
              <DataGridTextColumn Header="VSYS"      Binding="{Binding VSYS}"      Width="60"/>
              <DataGridTextColumn Header="VLAN"      Binding="{Binding VLAN}"      Width="*"/>
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
      <TabItem Header="📦 Content">
        <Grid Background="#1A1A2C">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <Border Grid.Row="0" Background="#0F0F1E" Padding="8,6" Margin="0,0,0,2">
            <WrapPanel Orientation="Horizontal">
              <Button x:Name="btnFetchContent"    Content="↻ Fetch (Selected)" Style="{StaticResource BtnGreen}" IsEnabled="False" Padding="12,4"/>
              <Button x:Name="btnFetchContentAll" Content="↻ All"               Style="{StaticResource Btn}"      IsEnabled="False" Padding="10,4" Margin="4,0"/>
              <Button x:Name="btnExportContent"   Content="📥 Export CSV"      Style="{StaticResource BtnGray}"  Padding="10,4"/>
              <Button x:Name="btnForceContent"    Content="⬇ Force Update (Selected)" Style="{StaticResource BtnAmber}" IsEnabled="False" Padding="10,4" Margin="10,0,0,0" ToolTip="Check, download, and install latest Apps+Threats content on each selected firewall"/>
              <TextBlock x:Name="txtContentStatus" Text="" Foreground="#8888AA" FontSize="11" VerticalAlignment="Center" Margin="14,0,0,0"/>
            </WrapPanel>
          </Border>
          <DataGrid x:Name="dgContent" Grid.Row="1" AutoGenerateColumns="False" CanUserAddRows="False" IsReadOnly="True">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Hostname"  Binding="{Binding Hostname}"  Width="170"/>
              <DataGridTextColumn Header="App+Threat" Binding="{Binding AppThreat}" Width="120"/>
              <DataGridTextColumn Header="AntiVirus" Binding="{Binding AV}"         Width="110"/>
              <DataGridTextColumn Header="WildFire"  Binding="{Binding WildFire}"   Width="120"/>
              <DataGridTextColumn Header="URL DB"    Binding="{Binding URLDB}"      Width="110"/>
              <DataGridTextColumn Header="GP Data"   Binding="{Binding GPData}"     Width="110"/>
              <DataGridTextColumn Header="Uptime"    Binding="{Binding Uptime}"     Width="*"/>
            </DataGrid.Columns>
          </DataGrid>
        </Grid>
      </TabItem>
      <TabItem Header="🧹 SW Cleanup">
        <Grid Background="#1A1A2C">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <Border Grid.Row="0" Background="#0F0F1E" Padding="8,6" Margin="0,0,0,2">
            <WrapPanel Orientation="Horizontal">
              <Button x:Name="btnFetchSW"    Content="↻ Fetch Versions (Selected)" Style="{StaticResource BtnGreen}" IsEnabled="False" Padding="12,4"/>
              <Button x:Name="btnFetchSWAll" Content="↻ All"                        Style="{StaticResource Btn}"      IsEnabled="False" Padding="10,4" Margin="4,0"/>
              <Button x:Name="btnDeleteSW"   Content="✕ Delete Selected Images"     Style="{StaticResource BtnRed}"   IsEnabled="False" Padding="10,4" Margin="10,0,0,0" ToolTip="request system software delete version &lt;ver&gt; on each selected row's firewall"/>
              <Button x:Name="btnExportSW"   Content="📥 Export CSV"                Style="{StaticResource BtnGray}"  Padding="10,4" Margin="10,0,0,0"/>
              <CheckBox x:Name="cbSWDeletableOnly" Content="Deletable only" Style="{StaticResource FCB}" IsChecked="True" Margin="14,0,0,0" VerticalAlignment="Center" ToolTip="Show only downloaded, non-base maintenance images older than the running version"/>
              <TextBlock x:Name="txtSWStatus" Text="" Foreground="#8888AA" FontSize="11" VerticalAlignment="Center" Margin="14,0,0,0"/>
            </WrapPanel>
          </Border>
          <DataGrid x:Name="dgSW" Grid.Row="1" AutoGenerateColumns="False" CanUserAddRows="False" IsReadOnly="True" SelectionMode="Extended" SelectionUnit="FullRow">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Hostname"  Binding="{Binding Hostname}"  Width="170"/>
              <DataGridTextColumn Header="Version"   Binding="{Binding Version}"   Width="120"/>
              <DataGridTextColumn Header="Running"   Binding="{Binding Running}"   Width="70"/>
              <DataGridTextColumn Header="Downloaded" Binding="{Binding Downloaded}" Width="90"/>
              <DataGridTextColumn Header="Base Rel"  Binding="{Binding Base}"      Width="70"/>
              <DataGridTextColumn Header="Older"     Binding="{Binding Older}"     Width="60"/>
              <DataGridTextColumn Header="Deletable" Binding="{Binding Deletable}" Width="80"/>
              <DataGridTextColumn Header="Released"  Binding="{Binding Released}"  Width="170"/>
              <DataGridTextColumn Header="Size"      Binding="{Binding Size}"      Width="*"/>
            </DataGrid.Columns>
          </DataGrid>
        </Grid>
      </TabItem>
      <TabItem Header="📊 System">
        <Grid Background="#1A1A2C">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <Border Grid.Row="0" Background="#0F0F1E" Padding="8,6" Margin="0,0,0,2">
            <WrapPanel Orientation="Horizontal">
              <Button x:Name="btnFetchSystem"    Content="↻ Fetch (Selected)" Style="{StaticResource BtnGreen}" IsEnabled="False" Padding="12,4"/>
              <Button x:Name="btnFetchSystemAll" Content="↻ All"               Style="{StaticResource Btn}"      IsEnabled="False" Padding="10,4" Margin="4,0"/>
              <Button x:Name="btnExportSystem"   Content="📥 Export CSV"      Style="{StaticResource BtnGray}"  Padding="10,4"/>
              <TextBlock x:Name="txtSystemStatus" Text="" Foreground="#8888AA" FontSize="11" VerticalAlignment="Center" Margin="14,0,0,0"/>
            </WrapPanel>
          </Border>
          <DataGrid x:Name="dgSystem" Grid.Row="1" AutoGenerateColumns="False" CanUserAddRows="False" IsReadOnly="True">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Hostname"  Binding="{Binding Hostname}"  Width="180"/>
              <DataGridTextColumn Header="Uptime"    Binding="{Binding Uptime}"    Width="180"/>
              <DataGridTextColumn Header="CPU %"     Binding="{Binding CPU}"       Width="80"/>
              <DataGridTextColumn Header="Mem %"     Binding="{Binding Mem}"       Width="80"/>
              <DataGridTextColumn Header="Disk %"    Binding="{Binding Disk}"      Width="80"/>
              <DataGridTextColumn Header="Sessions"  Binding="{Binding Sessions}"  Width="100"/>
              <DataGridTextColumn Header="Notes"     Binding="{Binding Notes}"     Width="*"/>
            </DataGrid.Columns>
          </DataGrid>
        </Grid>
      </TabItem>
      <TabItem Header="📝 Commits">
        <Grid Background="#1A1A2C">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <Border Grid.Row="0" Background="#0F0F1E" Padding="8,6" Margin="0,0,0,2">
            <WrapPanel Orientation="Horizontal">
              <Button x:Name="btnFetchCommits"    Content="↻ Fetch (Selected)" Style="{StaticResource BtnGreen}" IsEnabled="False" Padding="12,4"/>
              <Button x:Name="btnFetchCommitsAll" Content="↻ All"               Style="{StaticResource Btn}"      IsEnabled="False" Padding="10,4" Margin="4,0"/>
              <Button x:Name="btnExportCommits"   Content="📥 Export CSV"      Style="{StaticResource BtnGray}"  Padding="10,4"/>
              <TextBlock x:Name="txtCommitsStatus" Text="" Foreground="#8888AA" FontSize="11" VerticalAlignment="Center" Margin="14,0,0,0"/>
            </WrapPanel>
          </Border>
          <DataGrid x:Name="dgCommits" Grid.Row="1" AutoGenerateColumns="False" CanUserAddRows="False" IsReadOnly="True">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Hostname"    Binding="{Binding Hostname}"    Width="180"/>
              <DataGridTextColumn Header="JobID"       Binding="{Binding JobID}"       Width="70"/>
              <DataGridTextColumn Header="Type"        Binding="{Binding JobType}"     Width="80"/>
              <DataGridTextColumn Header="Status"      Binding="{Binding Status}"      Width="80"/>
              <DataGridTextColumn Header="Result"      Binding="{Binding Result}"      Width="80"/>
              <DataGridTextColumn Header="Admin"       Binding="{Binding Admin}"       Width="150"/>
              <DataGridTextColumn Header="Queued"      Binding="{Binding TimeQueued}"  Width="160"/>
              <DataGridTextColumn Header="Ended"       Binding="{Binding TimeEnded}"   Width="160"/>
              <DataGridTextColumn Header="Description" Binding="{Binding Description}" Width="*"/>
            </DataGrid.Columns>
          </DataGrid>
        </Grid>
      </TabItem>
      <TabItem Header="🌐 GP Users">
        <Grid Background="#1A1A2C">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <Border Grid.Row="0" Background="#0F0F1E" Padding="8,6" Margin="0,0,0,2">
            <WrapPanel Orientation="Horizontal">
              <Button x:Name="btnFetchGP"    Content="↻ Fetch (Selected)" Style="{StaticResource BtnGreen}" IsEnabled="False" Padding="12,4"/>
              <Button x:Name="btnFetchGPAll" Content="↻ All"               Style="{StaticResource Btn}"      IsEnabled="False" Padding="10,4" Margin="4,0"/>
              <Button x:Name="btnExportGP"   Content="📥 Export CSV"      Style="{StaticResource BtnGray}"  Padding="10,4"/>
              <Label Content="Filter user/IP:" Style="{StaticResource Lbl}" Margin="10,0,0,0"/>
              <TextBox x:Name="txtGPFilter" Width="160" Style="{StaticResource TBox}" ToolTip="Regex matched against username/computer/IP"/>
              <Button x:Name="btnGPClearFilter" Content="✕" Style="{StaticResource BtnGray}" Padding="6,4"/>
              <CheckBox x:Name="cbGPHideRemote" Content="Hide remote (virtual IP)" IsChecked="False" Foreground="#CCC" VerticalAlignment="Center" Margin="12,0,0,0" ToolTip="Hide entries that have a real virtual IP (remote VPN users)."/>
              <CheckBox x:Name="cbGPHideInternal" Content="Hide internal GW (vIP 0.0.0.0)" IsChecked="False" Foreground="#CCC" VerticalAlignment="Center" Margin="10,0,0,0" ToolTip="Hide entries whose virtual IP is 0.0.0.0 (internal gateway used for User-ID mapping only)."/>
              <CheckBox x:Name="cbGPDedup" Content="Hide duplicate users" IsChecked="False" Foreground="#CCC" VerticalAlignment="Center" Margin="10,0,0,0" ToolTip="Collapse the same username appearing on both HA peers (FW01/FW02 share GP state)."/>
              <TextBlock x:Name="txtGPStatus" Text="" Foreground="#8888AA" FontSize="11" VerticalAlignment="Center" Margin="14,0,0,0"/>
            </WrapPanel>
          </Border>
          <DataGrid x:Name="dgGP" Grid.Row="1" AutoGenerateColumns="False" CanUserAddRows="False" IsReadOnly="True">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Gateway"   Binding="{Binding Hostname}"   Width="180"/>
              <DataGridTextColumn Header="Username"  Binding="{Binding Username}"   Width="180"/>
              <DataGridTextColumn Header="Computer"  Binding="{Binding Computer}"   Width="180"/>
              <DataGridTextColumn Header="Client IP" Binding="{Binding ClientIP}"   Width="120"/>
              <DataGridTextColumn Header="Virtual IP" Binding="{Binding VirtualIP}" Width="120"/>
              <DataGridTextColumn Header="Public IP" Binding="{Binding PublicIP}"   Width="120"/>
              <DataGridTextColumn Header="Login"     Binding="{Binding LoginTime}"  Width="170"/>
              <DataGridTextColumn Header="OS"        Binding="{Binding OS}"         Width="*"/>
            </DataGrid.Columns>
          </DataGrid>
        </Grid>
      </TabItem>
      <TabItem Header="🌊 Sessions">
        <Grid Background="#1A1A2C">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <Border Grid.Row="0" Background="#0F0F1E" Padding="8,6" Margin="0,0,0,2">
            <WrapPanel Orientation="Horizontal">
              <Button x:Name="btnFetchSessions"    Content="↻ Fetch (Selected)" Style="{StaticResource BtnGreen}" IsEnabled="False" Padding="12,4"/>
              <Button x:Name="btnFetchSessionsAll" Content="↻ All"              Style="{StaticResource Btn}"      IsEnabled="False" Padding="10,4" Margin="4,0"/>
              <Button x:Name="btnExportSessions"   Content="📥 Export CSV"      Style="{StaticResource BtnGray}"  Padding="10,4"/>
              <Button x:Name="btnClearSessions"    Content="✕ Clear Selected Sessions" Style="{StaticResource BtnRed}" IsEnabled="False" Padding="10,4" Margin="10,0,0,0" ToolTip="Select one or more rows in the grid below, then click to clear those sessions on their firewalls"/>
              <Label Content="Filter:" Style="{StaticResource Lbl}" Margin="10,0,0,0"/>
              <TextBox x:Name="txtSessionFilter" Width="320" Style="{StaticResource TBox}" ToolTip="Space-separated key=value pairs. Keys: src, dst, app, user, proto (tcp/udp/icmp/N), sport, dport, state (active/discard/initial/opening). Example: src=10.1.1.5 app=ssh"/>
              <Label Content="Cap:" Style="{StaticResource Lbl}" Margin="6,0,0,0"/>
              <TextBox x:Name="txtSessionCap" Width="60" Style="{StaticResource TBox}" Text="500" ToolTip="Max sessions returned per firewall (PAN-OS default cap is 1024)"/>
              <TextBlock x:Name="txtSessionsStatus" Text="" Foreground="#8888AA" FontSize="11" VerticalAlignment="Center" Margin="14,0,0,0"/>
            </WrapPanel>
          </Border>
          <DataGrid x:Name="dgSessions" Grid.Row="1" AutoGenerateColumns="False" CanUserAddRows="False" IsReadOnly="True" SelectionMode="Extended" SelectionUnit="FullRow">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Hostname"    Binding="{Binding Hostname}"    Width="170"/>
              <DataGridTextColumn Header="ID"          Binding="{Binding SessionID}"   Width="70"/>
              <DataGridTextColumn Header="From"        Binding="{Binding FromZone}"    Width="90"/>
              <DataGridTextColumn Header="To"          Binding="{Binding ToZone}"      Width="90"/>
              <DataGridTextColumn Header="Source"      Binding="{Binding Source}"      Width="130"/>
              <DataGridTextColumn Header="SPort"       Binding="{Binding SPort}"       Width="60"/>
              <DataGridTextColumn Header="Destination" Binding="{Binding Destination}" Width="130"/>
              <DataGridTextColumn Header="DPort"       Binding="{Binding DPort}"       Width="60"/>
              <DataGridTextColumn Header="Proto"       Binding="{Binding Protocol}"    Width="60"/>
              <DataGridTextColumn Header="App"         Binding="{Binding Application}" Width="120"/>
              <DataGridTextColumn Header="User"        Binding="{Binding SrcUser}"     Width="160"/>
              <DataGridTextColumn Header="State"       Binding="{Binding State}"       Width="80"/>
              <DataGridTextColumn Header="Type"        Binding="{Binding Type}"        Width="*"/>
            </DataGrid.Columns>
          </DataGrid>
        </Grid>
      </TabItem>
      <TabItem Header="🔒 Certs">
        <Grid Background="#1A1A2C">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <Border Grid.Row="0" Background="#0F0F1E" Padding="8,6" Margin="0,0,0,2">
            <WrapPanel Orientation="Horizontal">
              <Button x:Name="btnFetchCerts"    Content="↻ Fetch (Selected)" Style="{StaticResource BtnGreen}" IsEnabled="False" Padding="12,4"/>
              <Button x:Name="btnFetchCertsAll" Content="↻ All"              Style="{StaticResource Btn}"      IsEnabled="False" Padding="10,4" Margin="4,0"/>
              <Button x:Name="btnExportCerts"   Content="📥 Export CSV"      Style="{StaticResource BtnGray}"  Padding="10,4"/>
              <Label Content="Filter:" Style="{StaticResource Lbl}" Margin="10,0,0,0"/>
              <TextBox x:Name="txtCertFilter" Width="200" Style="{StaticResource TBox}" ToolTip="Regex matched against cert name/CN/issuer"/>
              <Button x:Name="btnCertClearFilter" Content="✕" Style="{StaticResource BtnGray}" Padding="6,4"/>
              <Label Content="≤ days:" Style="{StaticResource Lbl}" Margin="6,0,0,0"/>
              <TextBox x:Name="txtCertDays" Width="60" Style="{StaticResource TBox}" ToolTip="Show only certs expiring within N days; blank = all"/>
              <TextBlock x:Name="txtCertsStatus" Text="" Foreground="#8888AA" FontSize="11" VerticalAlignment="Center" Margin="14,0,0,0"/>
            </WrapPanel>
          </Border>
          <DataGrid x:Name="dgCerts" Grid.Row="1" AutoGenerateColumns="False" CanUserAddRows="False" IsReadOnly="True">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Hostname"     Binding="{Binding Hostname}"      Width="160"/>
              <DataGridTextColumn Header="Cert Name"    Binding="{Binding CertName}"      Width="200"/>
              <DataGridTextColumn Header="Common Name"  Binding="{Binding CN}"            Width="200"/>
              <DataGridTextColumn Header="Issuer"       Binding="{Binding Issuer}"        Width="200"/>
              <DataGridTextColumn Header="Not Before"   Binding="{Binding NotBefore}"     Width="130"/>
              <DataGridTextColumn Header="Not After"    Binding="{Binding NotAfter}"      Width="130"/>
              <DataGridTextColumn Header="Days Left"    Binding="{Binding DaysLeft}"      Width="80"/>
              <DataGridTextColumn Header="Priv Key"     Binding="{Binding HasPrivateKey}" Width="70"/>
              <DataGridTextColumn Header="Status"       Binding="{Binding Status}"        Width="*"/>
            </DataGrid.Columns>
          </DataGrid>
        </Grid>
      </TabItem>
      <TabItem Header="🛰 Ping/Trace">
        <Grid Background="#1A1A2C">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <Border Grid.Row="0" Background="#0F0F1E" Padding="8,6" Margin="0,0,0,2">
            <WrapPanel Orientation="Horizontal">
              <Label Content="From firewall:" Style="{StaticResource Lbl}"/>
              <ComboBox x:Name="cbPingFW" Width="220" DisplayMemberPath="Hostname"/>
              <Button x:Name="btnPingLoadIfaces" Content="↻ Load Interfaces" Style="{StaticResource Btn}" IsEnabled="False" Padding="10,4" Margin="6,0,0,0"/>
              <Label Content="Source IP:" Style="{StaticResource Lbl}" Margin="10,0,0,0"/>
              <ComboBox x:Name="cbPingSrc" Width="220" IsEditable="True" ToolTip="Pick an interface IP (after Load Interfaces) or type any IP"/>
              <Label Content="Target:" Style="{StaticResource Lbl}" Margin="10,0,0,0"/>
              <TextBox x:Name="txtPingTarget" Width="180" Style="{StaticResource TBox}"/>
              <Label Content="Count:" Style="{StaticResource Lbl}"/>
              <TextBox x:Name="txtPingCount" Width="50" Style="{StaticResource TBox}" Text="5"/>
              <Button x:Name="btnRunPing"         Content="📍 Ping"       Style="{StaticResource BtnGreen}" IsEnabled="False" Padding="10,4" Margin="10,0,0,0"/>
              <Button x:Name="btnRunTrace"        Content="🗺 Traceroute" Style="{StaticResource Btn}"      IsEnabled="False" Padding="10,4"/>
              <Button x:Name="btnClearPingOutput" Content="✕ Clear Output" Style="{StaticResource BtnGray}" Padding="6,4" Margin="10,0,0,0"/>
            </WrapPanel>
          </Border>
          <Border Grid.Row="1" Background="#0F0F1E" Padding="8,4" Margin="0,0,0,2">
            <TextBlock x:Name="txtPingStatus" Text="⚠ Note: PAN-OS XML API blocks &lt;ping&gt;/&lt;traceroute&gt; on most builds (returns error 17). If the output below shows that error, use the firewall's Web UI → Network → Troubleshooting → Ping, or SSH to the firewall directly." Foreground="#E0B040" FontSize="11" TextWrapping="Wrap"/>
          </Border>
          <TextBox x:Name="txtPingOutput" Grid.Row="2" Background="#000" Foreground="#0F0" FontFamily="Consolas" FontSize="11" IsReadOnly="True" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" TextWrapping="NoWrap" AcceptsReturn="True"/>
        </Grid>
      </TabItem>
      <TabItem Header="🌐 Routing Peers">
        <Grid Background="#1A1A2C">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <Border Grid.Row="0" Background="#0F0F1E" Padding="8,6" Margin="0,0,0,2">
            <WrapPanel Orientation="Horizontal">
              <Button x:Name="btnFetchPeers"    Content="↻ Fetch (Selected)" Style="{StaticResource BtnGreen}" IsEnabled="False" Padding="12,4"/>
              <Button x:Name="btnFetchPeersAll" Content="↻ All"              Style="{StaticResource Btn}"      IsEnabled="False" Padding="10,4" Margin="4,0"/>
              <Button x:Name="btnExportPeers"   Content="📥 Export CSV"      Style="{StaticResource BtnGray}"  Padding="10,4"/>
              <CheckBox x:Name="cbPeersBGP"  Content="BGP"  IsChecked="True" Foreground="#CCC" VerticalAlignment="Center" Margin="14,0,0,0"/>
              <CheckBox x:Name="cbPeersOSPF" Content="OSPF" IsChecked="True" Foreground="#CCC" VerticalAlignment="Center" Margin="6,0,0,0"/>
              <CheckBox x:Name="cbPeersOnlyDown" Content="Only show down/non-Established" Foreground="#CCC" VerticalAlignment="Center" Margin="14,0,0,0"/>
              <TextBlock x:Name="txtPeersStatus" Text="" Foreground="#8888AA" FontSize="11" VerticalAlignment="Center" Margin="14,0,0,0"/>
            </WrapPanel>
          </Border>
          <DataGrid x:Name="dgPeers" Grid.Row="1" AutoGenerateColumns="False" CanUserAddRows="False" IsReadOnly="True">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Hostname" Binding="{Binding Hostname}" Width="170"/>
              <DataGridTextColumn Header="VR"       Binding="{Binding VR}"       Width="100"/>
              <DataGridTextColumn Header="Protocol" Binding="{Binding Protocol}" Width="70"/>
              <DataGridTextColumn Header="Peer"     Binding="{Binding PeerName}" Width="170"/>
              <DataGridTextColumn Header="Address"  Binding="{Binding PeerAddr}" Width="180"/>
              <DataGridTextColumn Header="AS/Area"  Binding="{Binding ASNArea}"  Width="100"/>
              <DataGridTextColumn Header="State"    Binding="{Binding State}"    Width="120"/>
              <DataGridTextColumn Header="Uptime"   Binding="{Binding Uptime}"   Width="130"/>
              <DataGridTextColumn Header="Notes"    Binding="{Binding Notes}"    Width="*"/>
            </DataGrid.Columns>
          </DataGrid>
        </Grid>
      </TabItem>
      <TabItem Header="🔁 HA Drift">
        <Grid Background="#1A1A2C">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <Border Grid.Row="0" Background="#0F0F1E" Padding="8,6" Margin="0,0,0,2">
            <WrapPanel Orientation="Horizontal">
              <Button x:Name="btnFetchDrift"    Content="↻ Check (Selected)" Style="{StaticResource BtnGreen}" IsEnabled="False" Padding="12,4"/>
              <Button x:Name="btnFetchDriftAll" Content="↻ All"              Style="{StaticResource Btn}"      IsEnabled="False" Padding="10,4" Margin="4,0"/>
              <Button x:Name="btnExportDrift"   Content="📥 Export CSV"      Style="{StaticResource BtnGray}"  Padding="10,4"/>
              <CheckBox x:Name="cbDriftOnlyMismatch" Content="Only mismatches" Foreground="#CCC" VerticalAlignment="Center" Margin="14,0,0,0"/>
              <TextBlock x:Name="txtDriftStatus" Text="" Foreground="#8888AA" FontSize="11" VerticalAlignment="Center" Margin="14,0,0,0"/>
            </WrapPanel>
          </Border>
          <DataGrid x:Name="dgDrift" Grid.Row="1" AutoGenerateColumns="False" CanUserAddRows="False" IsReadOnly="True">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Hostname"      Binding="{Binding Hostname}"      Width="170"/>
              <DataGridTextColumn Header="Local State"   Binding="{Binding LocalState}"    Width="90"/>
              <DataGridTextColumn Header="Peer IP"       Binding="{Binding PeerMgmtIP}"    Width="120"/>
              <DataGridTextColumn Header="Peer State"    Binding="{Binding PeerState}"     Width="90"/>
              <DataGridTextColumn Header="Config Sync"   Binding="{Binding ConfigSync}"    Width="120"/>
              <DataGridTextColumn Header="State Sync"    Binding="{Binding StateSync}"     Width="100"/>
              <DataGridTextColumn Header="App Ver Match" Binding="{Binding AppVerMatch}"   Width="100"/>
              <DataGridTextColumn Header="SW Ver Match"  Binding="{Binding SwVerMatch}"    Width="100"/>
              <DataGridTextColumn Header="Local Pri"     Binding="{Binding LocalPriority}" Width="70"/>
              <DataGridTextColumn Header="Peer Pri"      Binding="{Binding PeerPriority}"  Width="70"/>
              <DataGridTextColumn Header="Notes"         Binding="{Binding Notes}"         Width="*"/>
            </DataGrid.Columns>
          </DataGrid>
        </Grid>
      </TabItem>
      <TabItem Header="📶 GP Gateways">
        <Grid Background="#1A1A2C">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <Border Grid.Row="0" Background="#0F0F1E" Padding="8,6" Margin="0,0,0,2">
            <WrapPanel Orientation="Horizontal">
              <Button x:Name="btnFetchGW"    Content="↻ Fetch (Selected DC)" Style="{StaticResource BtnGreen}" IsEnabled="False" Padding="12,4"/>
              <Button x:Name="btnFetchGWAll" Content="↻ All DC"               Style="{StaticResource Btn}"      IsEnabled="False" Padding="10,4" Margin="4,0"/>
              <Button x:Name="btnExportGW"   Content="📥 Export CSV"          Style="{StaticResource BtnGray}"  Padding="10,4"/>
              <TextBlock x:Name="txtGWStatus" Text="" Foreground="#8888AA" FontSize="11" VerticalAlignment="Center" Margin="14,0,0,0"/>
            </WrapPanel>
          </Border>
          <DataGrid x:Name="dgGW" Grid.Row="1" AutoGenerateColumns="False" CanUserAddRows="False" IsReadOnly="True">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Firewall"      Binding="{Binding Hostname}"     Width="180"/>
              <DataGridTextColumn Header="Gateway"       Binding="{Binding GatewayName}"  Width="220"/>
              <DataGridTextColumn Header="Tunnel"        Binding="{Binding TunnelName}"   Width="140"/>
              <DataGridTextColumn Header="Active Users"  Binding="{Binding ActiveUsers}"  Width="100"/>
              <DataGridTextColumn Header="Max Users"     Binding="{Binding MaxUsers}"     Width="100"/>
              <DataGridTextColumn Header="SSL"           Binding="{Binding SSLUsers}"     Width="80"/>
              <DataGridTextColumn Header="IPsec"         Binding="{Binding IPsecUsers}"   Width="80"/>
              <DataGridTextColumn Header="Notes"         Binding="{Binding Notes}"        Width="*"/>
            </DataGrid.Columns>
          </DataGrid>
        </Grid>
      </TabItem>
      <TabItem Header="🔍 Policy Match">
        <Grid Background="#1A1A2C">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <Border Grid.Row="0" Background="#0F0F1E" Padding="8,6" Margin="0,0,0,2">
            <Grid>
              <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
              <WrapPanel Grid.Row="0" Orientation="Horizontal">
                <Label Content="Src:" Style="{StaticResource Lbl}"/>
                <TextBox x:Name="txtPMSrc"   Width="120" Style="{StaticResource TBox}" ToolTip="Source IP (required)"/>
                <Label Content="Dst:" Style="{StaticResource Lbl}"/>
                <TextBox x:Name="txtPMDst"   Width="120" Style="{StaticResource TBox}" ToolTip="Destination IP (required)"/>
                <Label Content="DPort:" Style="{StaticResource Lbl}"/>
                <TextBox x:Name="txtPMDPort" Width="60"  Style="{StaticResource TBox}" Text="443" ToolTip="Destination port (required)"/>
                <Label Content="Proto:" Style="{StaticResource Lbl}"/>
                <TextBox x:Name="txtPMProto" Width="60"  Style="{StaticResource TBox}" Text="6"   ToolTip="IP protocol NUMBER (6=tcp, 17=udp, 1=icmp)"/>
                <Label Content="App:" Style="{StaticResource Lbl}"/>
                <TextBox x:Name="txtPMApp"   Width="120" Style="{StaticResource TBox}" ToolTip="App-ID name (optional, e.g. ssh, web-browsing)"/>
              </WrapPanel>
              <WrapPanel Grid.Row="1" Orientation="Horizontal" Margin="0,4,0,0">
                <Label Content="User:" Style="{StaticResource Lbl}"/>
                <TextBox x:Name="txtPMUser" Width="160" Style="{StaticResource TBox}" ToolTip="Source user (optional)"/>
                <Label Content="From zone:" Style="{StaticResource Lbl}" Margin="6,0,0,0"/>
                <TextBox x:Name="txtPMFrom" Width="100" Style="{StaticResource TBox}" ToolTip="From zone (optional)"/>
                <Label Content="To zone:" Style="{StaticResource Lbl}"/>
                <TextBox x:Name="txtPMTo"   Width="100" Style="{StaticResource TBox}" ToolTip="To zone (optional)"/>
                <CheckBox x:Name="cbPMShowAll" Content="Show all matches" IsChecked="True" Foreground="#CCC" VerticalAlignment="Center" Margin="10,0,0,0"/>
                <Button x:Name="btnRunPM"    Content="🔍 Test (Selected)" Style="{StaticResource BtnGreen}" IsEnabled="False" Padding="12,4" Margin="14,0,0,0"/>
                <Button x:Name="btnRunPMAll" Content="🔍 Test All"        Style="{StaticResource Btn}"      IsEnabled="False" Padding="10,4" Margin="4,0"/>
                <Button x:Name="btnExportPM" Content="📥 Export CSV"      Style="{StaticResource BtnGray}"  Padding="10,4"/>
                <TextBlock x:Name="txtPMStatus" Text="" Foreground="#8888AA" FontSize="11" VerticalAlignment="Center" Margin="14,0,0,0"/>
              </WrapPanel>
            </Grid>
          </Border>
          <DataGrid x:Name="dgPM" Grid.Row="1" AutoGenerateColumns="False" CanUserAddRows="False" IsReadOnly="True">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Hostname"  Binding="{Binding Hostname}"  Width="180"/>
              <DataGridTextColumn Header="Index"     Binding="{Binding Idx}"       Width="60"/>
              <DataGridTextColumn Header="Rule"      Binding="{Binding RuleName}"  Width="220"/>
              <DataGridTextColumn Header="Action"    Binding="{Binding Action}"    Width="90"/>
              <DataGridTextColumn Header="From"      Binding="{Binding FromZone}"  Width="100"/>
              <DataGridTextColumn Header="To"        Binding="{Binding ToZone}"    Width="100"/>
              <DataGridTextColumn Header="App"       Binding="{Binding App}"       Width="140"/>
              <DataGridTextColumn Header="Category"  Binding="{Binding Category}"  Width="120"/>
              <DataGridTextColumn Header="Terminal"  Binding="{Binding Terminal}"  Width="80"/>
              <DataGridTextColumn Header="Notes"     Binding="{Binding Notes}"     Width="*"/>
            </DataGrid.Columns>
          </DataGrid>
        </Grid>
      </TabItem>
      <TabItem Header="⛏ Rule Miner">
        <Grid Background="#1A1A2C">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="170"/></Grid.RowDefinitions>
          <Border Grid.Row="0" Background="#0F0F1E" Padding="8,6" Margin="0,0,0,2">
            <Grid>
              <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
              <WrapPanel Grid.Row="0" Orientation="Horizontal">
                <Label Content="Device group:" Style="{StaticResource Lbl}"/>
                <TextBox x:Name="txtRMDG" Width="150" Style="{StaticResource TBox}" ToolTip="Panorama device-group containing the broad rule. Used by Load Rules and in the generated CLI."/>
                <Button x:Name="btnRMLoadRules" Content="↻ Load Rules" Style="{StaticResource Btn}" IsEnabled="False" Padding="10,4" Margin="4,0" ToolTip="Read pre-rulebase security rule names from Panorama for this device-group"/>
                <Label Content="Rule:" Style="{StaticResource Lbl}" Margin="6,0,0,0"/>
                <ComboBox x:Name="cbRMRule" Width="220" IsEditable="True" ToolTip="The broad rule to mine (pick from list after Load Rules, or type a name)"/>
                <Label Content="Days:" Style="{StaticResource Lbl}" Margin="6,0,0,0"/>
                <TextBox x:Name="txtRMDays" Width="40" Style="{StaticResource TBox}" Text="7" ToolTip="Look-back window for traffic logs"/>
                <Label Content="Max logs:" Style="{StaticResource Lbl}"/>
                <TextBox x:Name="txtRMCap" Width="60" Style="{StaticResource TBox}" Text="20000" ToolTip="Total traffic logs to sample (API pages 5000 at a time). More = slower but more complete."/>
                <Button x:Name="btnRMFetch" Content="⛏ Mine Flows" Style="{StaticResource BtnGreen}" IsEnabled="False" Padding="12,4" Margin="8,0,0,0"/>
                <Button x:Name="btnExportRM" Content="📥 Export CSV" Style="{StaticResource BtnGray}" Padding="10,4" Margin="4,0"/>
                <TextBlock x:Name="txtRMStatus" Text="" Foreground="#8888AA" FontSize="11" VerticalAlignment="Center" Margin="14,0,0,0"/>
              </WrapPanel>
              <WrapPanel Grid.Row="1" Orientation="Horizontal" Margin="0,4,0,0">
                <Label Content="New rule prefix:" Style="{StaticResource Lbl}"/>
                <TextBox x:Name="txtRMPrefix" Width="70" Style="{StaticResource TBox}" Text="ZT-"/>
                <CheckBox x:Name="cbRMKnownUser" Content="source-user known-user" IsChecked="True" Foreground="#CCC" VerticalAlignment="Center" Margin="10,0,0,0" ToolTip="Match any User-ID-mapped user. UNCHECK for machine/service traffic (flows with few users vs sessions)."/>
                <CheckBox x:Name="cbRMSrcRestrict" Content="Restrict source to observed IPs" IsChecked="False" Foreground="#CCC" VerticalAlignment="Center" Margin="10,0,0,0" ToolTip="Embed observed source IPs / matched objects (max 20) instead of source any"/>
                <CheckBox x:Name="cbRMMatchObj" Content="Match address objects/groups" IsChecked="True" Foreground="#CCC" VerticalAlignment="Center" Margin="10,0,0,0" ToolTip="During Mine, match dst/src IPs against SHARED Panorama address objects and static groups; use object/group names in the CLI."/>
                <CheckBox x:Name="cbRMResolveLdap" Content="Resolve user groups (LDAP)" IsChecked="True" Foreground="#CCC" VerticalAlignment="Center" Margin="10,0,0,0" ToolTip="For flows with fewer than 'Max users', look up the flow's users in AD and suggest a matching group for source-user."/>
                <CheckBox x:Name="cbRMTransitive" Content="Transitive" IsChecked="False" Foreground="#CCC" VerticalAlignment="Center" Margin="6,0,0,0" ToolTip="Include nested (transitive) group membership via LDAP_MATCHING_RULE_IN_CHAIN. Slower."/>
                <Label Content="Max users:" Style="{StaticResource Lbl}" Margin="8,0,0,0"/>
                <TextBox x:Name="txtRMUserMax" Width="40" Style="{StaticResource TBox}" Text="50" ToolTip="Only resolve user groups for flows with fewer than this many distinct users."/>
                <Label Content="Cover %:" Style="{StaticResource Lbl}"/>
                <TextBox x:Name="txtRMCoverPct" Width="40" Style="{StaticResource TBox}" Text="80" ToolTip="A group must cover at least this % of a flow's sources (or users) to be suggested."/>
                <Rectangle Width="1" Fill="#333355" Margin="6,2"/>
                <Label Content="Region:" Style="{StaticResource Lbl}" ToolTip="Tag applied to created objects + used in naming (US / EU / APAC)."/>
                <TextBox x:Name="txtRMRegion" Width="44" Style="{StaticResource TBox}"/>
                <Label Content="Loc:" Style="{StaticResource Lbl}" ToolTip="3-letter location code (IRV / CH3 / DUS ...)."/>
                <TextBox x:Name="txtRMLoc" Width="44" Style="{StaticResource TBox}"/>
                <Label Content="Env:" Style="{StaticResource Lbl}"/>
                <TextBox x:Name="txtRMEnv" Width="48" Style="{StaticResource TBox}" Text="PROD" ToolTip="PROD / DEV / QA"/>
                <Label Content="Service:" Style="{StaticResource Lbl}" ToolTip="Service tag (SAP, Informatica...). Drives dynamic group names/filters; if blank, falls back to object/IP matching."/>
                <TextBox x:Name="txtRMService" Width="90" Style="{StaticResource TBox}"/>
                <Label Content="Profile:" Style="{StaticResource Lbl}"/>
                <TextBox x:Name="txtRMProfile" Width="110" Style="{StaticResource TBox}" Text="JH-Outbound-SP" ToolTip="Security profile group attached to generated rules (profile-setting group)."/>
                <CheckBox x:Name="cbRMCreateGroups" Content="Offer create-group CLI" IsChecked="True" Foreground="#CCC" VerticalAlignment="Center" Margin="10,0,0,0" ToolTip="When sources don't match an existing address-group, emit CLI to create tagged address objects + a group, and emit a suggested new AD group with the flow's users. Requires 'Restrict source' for the source side."/>
                <Button x:Name="btnRMGenCli"   Content="⚙ Individual Rules" Style="{StaticResource BtnAmber}" Padding="12,4" Margin="14,0,0,0" ToolTip="One tight rule per selected flow. Copy/paste only — nothing is sent to Panorama."/>
                <Button x:Name="btnRMGenMerge" Content="⚙ Merge → 1 Rule"   Style="{StaticResource BtnAmber}" Padding="12,4" Margin="4,0"  ToolTip="Combine ALL selected flows into a single rule (union of destinations, apps/services, sources, users)."/>
                <Button x:Name="btnRMCopyCli" Content="📋 Copy CLI" Style="{StaticResource BtnGray}" Padding="10,4" Margin="4,0"/>
              </WrapPanel>
            </Grid>
          </Border>
          <DataGrid x:Name="dgRM" Grid.Row="1" AutoGenerateColumns="False" CanUserAddRows="False" IsReadOnly="True" SelectionMode="Extended" SelectionUnit="FullRow">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Sessions"   Binding="{Binding Sessions}"   Width="80"/>
              <DataGridTextColumn Header="From"       Binding="{Binding FromZone}"   Width="110"/>
              <DataGridTextColumn Header="To"         Binding="{Binding ToZone}"     Width="110"/>
              <DataGridTextColumn Header="Destination" Binding="{Binding Destination}" Width="130"/>
              <DataGridTextColumn Header="DPort"      Binding="{Binding DPort}"      Width="60"/>
              <DataGridTextColumn Header="Proto"      Binding="{Binding Protocol}"   Width="60"/>
              <DataGridTextColumn Header="App"        Binding="{Binding App}"        Width="140"/>
              <DataGridTextColumn Header="Users"      Binding="{Binding UserCount}"  Width="60"/>
              <DataGridTextColumn Header="Top Users"  Binding="{Binding TopUsers}"   Width="220"/>
              <DataGridTextColumn Header="Srcs"       Binding="{Binding SrcCount}"   Width="60"/>
              <DataGridTextColumn Header="Top Sources" Binding="{Binding TopSources}" Width="200"/>
              <DataGridTextColumn Header="GB"         Binding="{Binding GB}"         Width="70"/>
              <DataGridTextColumn Header="Dst Obj"    Binding="{Binding DstObj}"     Width="150"/>
              <DataGridTextColumn Header="Src Match"  Binding="{Binding SrcMatch}"   Width="180"/>
              <DataGridTextColumn Header="User Group" Binding="{Binding UserGroup}"  Width="190"/>
              <DataGridTextColumn Header="Actions"    Binding="{Binding Actions}"    Width="*"/>
            </DataGrid.Columns>
          </DataGrid>
          <Border Grid.Row="2" Background="#080810" CornerRadius="4" Padding="4" Margin="0,2,0,0">
            <TextBox x:Name="txtRMCli" FontFamily="Consolas" FontSize="11" Background="#080810" Foreground="#66FF88" BorderThickness="0" IsReadOnly="False" AcceptsReturn="True" TextWrapping="NoWrap" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"/>
          </Border>
        </Grid>
      </TabItem>
    </TabControl>

    <!-- ROW 4 : Action Bar (HA/SW/Cfg/Reboot) — shown only on the Devices tab -->
    <Border x:Name="brdActionBar" Grid.Row="4" Background="#0F0F1E" CornerRadius="6" Padding="10,7" Margin="0,0,0,6">
      <Grid>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <WrapPanel Grid.Column="0" Orientation="Horizontal">
          <Label Content="HA:" Style="{StaticResource Lbl}" FontWeight="SemiBold"/>
          <Button x:Name="btnRefreshHA" Content="↻ Refresh HA"   Style="{StaticResource Btn}"      IsEnabled="False"/>
          <Button x:Name="btnSyncHA"    Content="⟳ Sync Config"   Style="{StaticResource Btn}"      IsEnabled="False"/>
          <Button x:Name="btnSuspendHA" Content="⏸ Suspend"       Style="{StaticResource BtnRed}"   IsEnabled="False" ToolTip="request high-availability state suspend (triggers failover)"/>
          <Button x:Name="btnResumeHA"  Content="▶ Resume"        Style="{StaticResource BtnGreen}" IsEnabled="False" ToolTip="request high-availability state functional"/>
          <Button x:Name="btnSetPri70"  Content="⇈ 70 Force Primary"    Style="{StaticResource BtnRed}"   IsEnabled="False" ToolTip="Emergency: promote a passive/secondary firewall to primary"/>
          <Button x:Name="btnSetPri90"  Content="↑ 90 Primary"          Style="{StaticResource BtnAmber}" IsEnabled="False" ToolTip="Normal primary priority"/>
          <Button x:Name="btnSetPri110" Content="↓ 110 Secondary"       Style="{StaticResource BtnAmber}" IsEnabled="False" ToolTip="Normal secondary priority"/>
          <Button x:Name="btnSetPri130" Content="⇊ 130 Force Secondary" Style="{StaticResource BtnRed}"   IsEnabled="False" ToolTip="Emergency: demote an active/primary firewall to secondary"/>
          <Rectangle Width="1" Fill="#333355" Margin="6,2"/>
          <Label Content="SW:" Style="{StaticResource Lbl}" FontWeight="SemiBold"/>
          <Button x:Name="btnCheckDl"   Content="🔍 Check &amp; Download" Style="{StaticResource BtnGreen}" IsEnabled="False"/>
          <Button x:Name="btnInstall"   Content="⬇ Install"               Style="{StaticResource BtnGreen}" IsEnabled="False"/>
          <Button x:Name="btnCheckJobs" Content="📋 Job Status"            Style="{StaticResource Btn}"      IsEnabled="False"/>
          <Rectangle Width="1" Fill="#333355" Margin="6,2"/>
          <Label Content="Cfg:" Style="{StaticResource Lbl}" FontWeight="SemiBold"/>
          <Button x:Name="btnCommit"    Content="✓ Commit Selected"        Style="{StaticResource BtnAmber}" IsEnabled="False" ToolTip="Commit candidate config on each selected device"/>
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
$btnCheckJobs=Ctrl 'btnCheckJobs'; $btnReboot=Ctrl 'btnReboot'; $brdActionBar=Ctrl 'brdActionBar'
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

$btnFetchIf=Ctrl 'btnFetchIf'; $btnFetchIfAll=Ctrl 'btnFetchIfAll'; $btnExportIf=Ctrl 'btnExportIf'
$cbIfScope=Ctrl 'cbIfScope'; $txtIfZone=Ctrl 'txtIfZone'; $txtIfRegion=Ctrl 'txtIfRegion'
$txtIfFilter=Ctrl 'txtIfFilter'; $cbIfArp=Ctrl 'cbIfArp'; $btnIfClearFilter=Ctrl 'btnIfClearFilter'
$txtIfStatus=Ctrl 'txtIfStatus'; $dgIf=Ctrl 'dgIf'

$btnFetchLocks=Ctrl 'btnFetchLocks'; $btnFetchLocksAll=Ctrl 'btnFetchLocksAll'
$btnRemoveLocks=Ctrl 'btnRemoveLocks'; $btnExportLocks=Ctrl 'btnExportLocks'
$txtLocksStatus=Ctrl 'txtLocksStatus'; $dgLocks=Ctrl 'dgLocks'

$btnFetchEDLs=Ctrl 'btnFetchEDLs'; $btnRefreshEDLs=Ctrl 'btnRefreshEDLs'
$btnSelAllEDLs=Ctrl 'btnSelAllEDLs'; $btnSelNoneEDLs=Ctrl 'btnSelNoneEDLs'
$txtEDLStatus=Ctrl 'txtEDLStatus'; $dgEDLs=Ctrl 'dgEDLs'

# Batch 2 features
$btnSuspendHA=Ctrl 'btnSuspendHA'; $btnResumeHA=Ctrl 'btnResumeHA'; $btnCommit=Ctrl 'btnCommit'

$btnFetchContent=Ctrl 'btnFetchContent'; $btnFetchContentAll=Ctrl 'btnFetchContentAll'
$btnExportContent=Ctrl 'btnExportContent'; $txtContentStatus=Ctrl 'txtContentStatus'; $dgContent=Ctrl 'dgContent'

$btnFetchSW=Ctrl 'btnFetchSW'; $btnFetchSWAll=Ctrl 'btnFetchSWAll'; $btnDeleteSW=Ctrl 'btnDeleteSW'
$btnExportSW=Ctrl 'btnExportSW'; $cbSWDeletableOnly=Ctrl 'cbSWDeletableOnly'
$txtSWStatus=Ctrl 'txtSWStatus'; $dgSW=Ctrl 'dgSW'

$btnFetchSystem=Ctrl 'btnFetchSystem'; $btnFetchSystemAll=Ctrl 'btnFetchSystemAll'
$btnExportSystem=Ctrl 'btnExportSystem'; $txtSystemStatus=Ctrl 'txtSystemStatus'; $dgSystem=Ctrl 'dgSystem'

$btnFetchCommits=Ctrl 'btnFetchCommits'; $btnFetchCommitsAll=Ctrl 'btnFetchCommitsAll'
$btnExportCommits=Ctrl 'btnExportCommits'; $txtCommitsStatus=Ctrl 'txtCommitsStatus'; $dgCommits=Ctrl 'dgCommits'

$btnFetchGP=Ctrl 'btnFetchGP'; $btnFetchGPAll=Ctrl 'btnFetchGPAll'
$btnExportGP=Ctrl 'btnExportGP'; $txtGPFilter=Ctrl 'txtGPFilter'
$cbGPHideRemote=Ctrl 'cbGPHideRemote'; $cbGPHideInternal=Ctrl 'cbGPHideInternal'; $cbGPDedup=Ctrl 'cbGPDedup'
$btnGPClearFilter=Ctrl 'btnGPClearFilter'; $txtGPStatus=Ctrl 'txtGPStatus'; $dgGP=Ctrl 'dgGP'

# Batch 3 features (User-ID resync, ARP clear, IPsec clear, Content force update)
$btnResyncGroups=Ctrl 'btnResyncGroups'; $btnResyncCIE=Ctrl 'btnResyncCIE'
$btnClearARP=Ctrl 'btnClearARP'
$btnClearIPsec=Ctrl 'btnClearIPsec'
$btnForceContent=Ctrl 'btnForceContent'

# Sessions tab
$btnFetchSessions=Ctrl 'btnFetchSessions'; $btnFetchSessionsAll=Ctrl 'btnFetchSessionsAll'
$btnExportSessions=Ctrl 'btnExportSessions'; $btnClearSessions=Ctrl 'btnClearSessions'
$txtSessionFilter=Ctrl 'txtSessionFilter'; $txtSessionCap=Ctrl 'txtSessionCap'
$txtSessionsStatus=Ctrl 'txtSessionsStatus'; $dgSessions=Ctrl 'dgSessions'

# Batch 4 features: Certs, Ping/Trace, BGP/OSPF Peers, HA Drift, GP Gateways, Policy Match
$btnFetchCerts=Ctrl 'btnFetchCerts'; $btnFetchCertsAll=Ctrl 'btnFetchCertsAll'
$btnExportCerts=Ctrl 'btnExportCerts'; $txtCertFilter=Ctrl 'txtCertFilter'
$btnCertClearFilter=Ctrl 'btnCertClearFilter'; $txtCertDays=Ctrl 'txtCertDays'
$txtCertsStatus=Ctrl 'txtCertsStatus'; $dgCerts=Ctrl 'dgCerts'

$cbPingFW=Ctrl 'cbPingFW'; $btnPingLoadIfaces=Ctrl 'btnPingLoadIfaces'
$cbPingSrc=Ctrl 'cbPingSrc'; $txtPingTarget=Ctrl 'txtPingTarget'; $txtPingCount=Ctrl 'txtPingCount'
$btnRunPing=Ctrl 'btnRunPing'; $btnRunTrace=Ctrl 'btnRunTrace'
$btnClearPingOutput=Ctrl 'btnClearPingOutput'; $txtPingStatus=Ctrl 'txtPingStatus'
$txtPingOutput=Ctrl 'txtPingOutput'

$btnFetchPeers=Ctrl 'btnFetchPeers'; $btnFetchPeersAll=Ctrl 'btnFetchPeersAll'
$btnExportPeers=Ctrl 'btnExportPeers'; $cbPeersBGP=Ctrl 'cbPeersBGP'; $cbPeersOSPF=Ctrl 'cbPeersOSPF'
$cbPeersOnlyDown=Ctrl 'cbPeersOnlyDown'; $txtPeersStatus=Ctrl 'txtPeersStatus'; $dgPeers=Ctrl 'dgPeers'

$btnFetchDrift=Ctrl 'btnFetchDrift'; $btnFetchDriftAll=Ctrl 'btnFetchDriftAll'
$btnExportDrift=Ctrl 'btnExportDrift'; $cbDriftOnlyMismatch=Ctrl 'cbDriftOnlyMismatch'
$txtDriftStatus=Ctrl 'txtDriftStatus'; $dgDrift=Ctrl 'dgDrift'

$btnFetchGW=Ctrl 'btnFetchGW'; $btnFetchGWAll=Ctrl 'btnFetchGWAll'
$btnExportGW=Ctrl 'btnExportGW'; $txtGWStatus=Ctrl 'txtGWStatus'; $dgGW=Ctrl 'dgGW'

$txtPMSrc=Ctrl 'txtPMSrc'; $txtPMDst=Ctrl 'txtPMDst'; $txtPMDPort=Ctrl 'txtPMDPort'
$txtPMProto=Ctrl 'txtPMProto'; $txtPMApp=Ctrl 'txtPMApp'; $txtPMUser=Ctrl 'txtPMUser'
$txtPMFrom=Ctrl 'txtPMFrom'; $txtPMTo=Ctrl 'txtPMTo'; $cbPMShowAll=Ctrl 'cbPMShowAll'
$btnRunPM=Ctrl 'btnRunPM'; $btnRunPMAll=Ctrl 'btnRunPMAll'; $btnExportPM=Ctrl 'btnExportPM'
$txtPMStatus=Ctrl 'txtPMStatus'; $dgPM=Ctrl 'dgPM'

$txtRMDG=Ctrl 'txtRMDG'; $btnRMLoadRules=Ctrl 'btnRMLoadRules'; $cbRMRule=Ctrl 'cbRMRule'
$txtRMDays=Ctrl 'txtRMDays'; $txtRMCap=Ctrl 'txtRMCap'; $btnRMFetch=Ctrl 'btnRMFetch'
$btnExportRM=Ctrl 'btnExportRM'; $txtRMStatus=Ctrl 'txtRMStatus'; $txtRMPrefix=Ctrl 'txtRMPrefix'
$cbRMKnownUser=Ctrl 'cbRMKnownUser'; $cbRMSrcRestrict=Ctrl 'cbRMSrcRestrict'
$cbRMMatchObj=Ctrl 'cbRMMatchObj'; $cbRMResolveLdap=Ctrl 'cbRMResolveLdap'; $cbRMTransitive=Ctrl 'cbRMTransitive'
$txtRMUserMax=Ctrl 'txtRMUserMax'; $txtRMCoverPct=Ctrl 'txtRMCoverPct'
$txtRMRegion=Ctrl 'txtRMRegion'; $txtRMLoc=Ctrl 'txtRMLoc'; $txtRMEnv=Ctrl 'txtRMEnv'; $txtRMService=Ctrl 'txtRMService'; $txtRMProfile=Ctrl 'txtRMProfile'
$btnRMGenCli=Ctrl 'btnRMGenCli'; $btnRMGenMerge=Ctrl 'btnRMGenMerge'; $cbRMCreateGroups=Ctrl 'cbRMCreateGroups'; $btnRMCopyCli=Ctrl 'btnRMCopyCli'
$dgRM=Ctrl 'dgRM'; $txtRMCli=Ctrl 'txtRMCli'

$txtLog=Ctrl 'txtLog'; $svLog=Ctrl 'svLog'; $btnClearLog=Ctrl 'btnClearLog'

# ── Global state ─────────────────────────────────────────────
$script:AllDevices  = [System.Collections.Generic.List[object]]::new()
$script:DisplayColl = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$script:Connected   = $false
$script:PingCtrl       = [System.Collections.Hashtable]::Synchronized(@{ Stop = $false; Running = $false })
$script:RebootPollCtrl = [System.Collections.Hashtable]::Synchronized(@{ Stop = $false; Running = $false })

# Single-flight gate. Two pan-power runspaces cannot run at once — they
# corrupt each other's module state (HANDOFF dead-end §6.1). Held while any
# fetch is in flight; cleared by the fetch runspace as its last UI action.
$script:FetchLock = [System.Collections.Hashtable]::Synchronized(@{ Busy = $false; Name = '' })

# Action queue: when a fetch/action is in progress, further actions are enqueued here
# and run automatically (one at a time) by a DispatcherTimer once the lock clears.
$script:ActionQueue = New-Object 'System.Collections.Generic.Queue[object]'
$script:LastClicked = $null   # last button the user pressed (captured for queueing)

# Panorama credentials, captured on successful Connect. Used by Invoke-LicenseFetch
# to talk direct to each firewall (Panorama refuses to proxy show -> license).
# Synchronized so the Connect runspace can populate it; main thread reads it
# directly via dot access (no dispatcher needed for reads).
$script:PanCred = [System.Collections.Hashtable]::Synchronized(@{ IP=$null; User=$null; Pass=$null })

# DC firewalls — the only ones GP gateways run on. GP fetches are always
# restricted to this list regardless of selection. Branch firewalls have no
# GP gateway so querying them just wastes time.
$script:DataCenterFWs = @(
    '65028-US-IRV-FW01', '65028-US-IRV-FW02',
    '65031-US-CHI-FW01', '65031-US-CHI-FW02',
    '65093-AU-SY5-FW01', '65093-AU-SY5-FW02',
    '65095-AU-BR1-FW01',
    '65135-EU-DUS-FW01', '65135-EU-DUS-FW02',
    '65159-EU-FTS-FW01', '65159-EU-FTS-FW02'
)

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
$script:ColIfAll     = [System.Collections.Generic.List[object]]::new()
$script:ColIf        = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$script:ColLocks     = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$script:ColEDLs      = [System.Collections.ObjectModel.ObservableCollection[object]]::new()

$dgUserID.ItemsSource = $script:ColUserID
$dgARP.ItemsSource    = $script:ColARP
$dgIPsec.ItemsSource  = $script:ColIPsec
$dgRoutes.ItemsSource = $script:ColRoutes
$dgIf.ItemsSource     = $script:ColIf
$dgLocks.ItemsSource  = $script:ColLocks
$dgEDLs.ItemsSource   = $script:ColEDLs

$script:ColContent  = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$script:ColSWAll    = [System.Collections.Generic.List[object]]::new()
$script:ColSW       = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$script:ColSystem   = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$script:ColCommits  = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$script:ColGPAll    = [System.Collections.Generic.List[object]]::new()
$script:ColGP       = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$script:ColSessions = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$script:ColCertsAll = [System.Collections.Generic.List[object]]::new()
$script:ColCerts    = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$script:ColPeersAll = [System.Collections.Generic.List[object]]::new()
$script:ColPeers    = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$script:ColDriftAll = [System.Collections.Generic.List[object]]::new()
$script:ColDrift    = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$script:ColGW       = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$script:ColPM       = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$script:ColRM       = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
# Rule Miner: zones/action per rule, cached by Load Rules (rule name -> @{From;To;Action})
$script:RMRuleInfo  = [System.Collections.Hashtable]::Synchronized(@{})
# Existing-inventory caches (populated from Panorama during Mine) so generation reuses what already exists.
$script:RMTags    = [System.Collections.Hashtable]::Synchronized(@{})  # tag name        -> 1
$script:RMSvc     = [System.Collections.Hashtable]::Synchronized(@{})  # "proto/port"    -> existing service name
$script:RMGroups  = [System.Collections.Hashtable]::Synchronized(@{})  # address-group name -> 1
$script:RMObjTags = [System.Collections.Hashtable]::Synchronized(@{})  # address name    -> ';'-joined existing tags

$dgContent.ItemsSource  = $script:ColContent
$dgSW.ItemsSource       = $script:ColSW
$dgSystem.ItemsSource   = $script:ColSystem
$dgCommits.ItemsSource  = $script:ColCommits
$dgGP.ItemsSource       = $script:ColGP
$dgSessions.ItemsSource = $script:ColSessions
$dgCerts.ItemsSource    = $script:ColCerts
$dgPeers.ItemsSource    = $script:ColPeers
$dgDrift.ItemsSource    = $script:ColDrift
$dgGW.ItemsSource       = $script:ColGW
$dgPM.ItemsSource       = $script:ColPM
$dgRM.ItemsSource       = $script:ColRM
$cbPingFW.ItemsSource   = $script:DisplayColl

# ── Helpers ──────────────────────────────────────────────────
# Debug trace file. Always written so we can diagnose issues from screenshots
# alone — the in-window log scrolls and we lose detail. Located alongside the
# script. Use Write-Trace for verbose info (full exception text, request URLs,
# response shapes, etc.); Write-Log still goes to the UI for the user.
$script:TracePath = Join-Path $PSScriptRoot 'PANManager-debug.log'
try {
    # Truncate on startup so each session has its own log.
    "==== Session start: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ====" |
        Out-File -FilePath $script:TracePath -Encoding UTF8 -Force
} catch {}

function Write-Trace {
    param([string]$Msg, [string]$Tag = '')
    $ts = (Get-Date).ToString('HH:mm:ss.fff')
    $line = if ($Tag) { "[$ts] [$Tag] $Msg" } else { "[$ts] $Msg" }
    try { Add-Content -Path $script:TracePath -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
}

function Write-Log {
    param([string]$Msg)
    $ts   = (Get-Date).ToString('HH:mm:ss')
    $line = "[$ts] $Msg`n"
    # Mirror to the trace file always.
    try { Add-Content -Path $script:TracePath -Value "[$ts] [UI] $Msg" -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
    # Defensive: during shutdown the dispatcher is gone, controls may be null,
    # and even Get-Variable Window throws. Swallow everything so we don't spam
    # red text into a closing window or crash the host.
    try {
        if (-not $Window) { return }
        $Window.Dispatcher.Invoke([action]{
            try {
                if ($txtLog) { $txtLog.Text += $line }
                if ($svLog)  { $svLog.ScrollToBottom() }
            } catch {}
        }, 'Normal')
    } catch {}
}
function UI { param([scriptblock]$Block) $Window.Dispatcher.Invoke($Block, 'Normal') }

# Single-flight gate. Returns $false if another fetch is in progress.
function Begin-Fetch([string]$Name) {
    if ($script:FetchLock.Busy) {
        # Queue the action instead of rejecting it. We re-raise the click of the button
        # the user pressed (captured globally), so it runs automatically once the lock frees.
        $btn = $script:LastClicked
        $dup = @($script:ActionQueue.ToArray() | Where-Object { $_.Label -eq $Name })
        if ($btn -and $dup.Count -eq 0) {
            $script:ActionQueue.Enqueue([pscustomobject]@{ Button=$btn; Label=$Name })
            Write-Log "[$Name] '$($script:FetchLock.Name)' is running - added to queue (now $($script:ActionQueue.Count) waiting)."
        } else {
            Write-Log "[$Name] '$($script:FetchLock.Name)' is in progress - '$Name' already queued or cannot be queued; wait for it to finish."
        }
        return $false
    }
    $script:FetchLock.Busy = $true
    $script:FetchLock.Name = $Name
    return $true
}

# Confirmation for state-changing actions. Returns $true only if the user clicks Yes.
function Confirm-Impact([string]$Title, [string]$Detail) {
    $r = [System.Windows.MessageBox]::Show($Detail, "Confirm: $Title", 'YesNo', 'Warning')
    return ($r -eq 'Yes')
}

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
        foreach ($btn in @($btnRefreshHA,$btnSyncHA,$btnSuspendHA,$btnResumeHA,
                           $btnSetPri70,$btnSetPri90,$btnSetPri110,$btnSetPri130,
                           $btnCheckDl,$btnInstall,$btnCheckJobs,$btnCommit,$btnReboot,
                           $btnFetchLicenses,$btnFetchLicAll,
                           $btnFetchUserID,$btnFetchUserIDAll,$btnResyncGroups,$btnResyncCIE,
                           $btnFetchARP,$btnFetchARPAll,$btnClearARP,
                           $btnFetchIPsec,$btnFetchIPsecAll,$btnClearIPsec,
                           $btnFetchRoutes,$btnFetchRoutesAll,
                           $btnFetchIf,$btnFetchIfAll,
                           $btnFetchLocks,$btnFetchLocksAll,$btnRemoveLocks,
                           $btnFetchEDLs,$btnRefreshEDLs,
                           $btnFetchContent,$btnFetchContentAll,$btnForceContent,
                           $btnFetchSW,$btnFetchSWAll,
                           $btnFetchSystem,$btnFetchSystemAll,
                           $btnFetchCommits,$btnFetchCommitsAll,
                           $btnFetchGP,$btnFetchGPAll,
                           $btnFetchSessions,$btnFetchSessionsAll,$btnClearSessions,
                           $btnFetchCerts,$btnFetchCertsAll,
                           $btnPingLoadIfaces,$btnRunPing,$btnRunTrace,
                           $btnFetchPeers,$btnFetchPeersAll,
                           $btnFetchDrift,$btnFetchDriftAll,
                           $btnFetchGW,$btnFetchGWAll,
                           $btnRunPM,$btnRunPMAll,
                           $btnRMLoadRules,$btnRMFetch)) {
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
    $rs.SessionStateProxy.SetVariable('panCred',       $script:PanCred)

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
        # Stash creds via the synchronized hashtable so the main script's
        # $script:PanCred sees them (a $script: assignment inside this runspace
        # would only set the runspace's own scope).
        if ($ok) {
            $panCred.IP   = $ip
            $panCred.User = $user
            $panCred.Pass = $plainPass
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
    if (-not (Begin-Fetch 'HA Refresh')) { return }
    Write-Log "Refreshing HA for $($sel.Count) device(s)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('sel',$sel)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('updateStatsFn',${function:Update-Stats})
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
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
        UI {
            & $updateStatsFn
            $fetchLock.Busy = $false; $fetchLock.Name = ''
        }
        Log "HA refresh done."
    })
    [void]$ps.BeginInvoke()
})

# ── Sync HA config (active -> passive) ──────────────────────
$btnSyncHA.Add_Click({
    $sel = @($script:DisplayColl | Where-Object { $_.Selected -and $_.HAState -eq 'active' })
    if ($sel.Count -eq 0) { Write-Log "Select active HA devices to sync."; return }
    if (-not (Begin-Fetch 'HA Sync')) { return }
    Write-Log "Syncing HA config for $($sel.Count) active device(s)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('sel',$sel)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b) { $Window.Dispatcher.Invoke($b, 'Normal') }
        foreach ($dev in $sel) {
            try {
                $r = Invoke-PANOperation -Command "<request><high-availability><sync-to-remote><running-config/></sync-to-remote></high-availability></request>" -Target $dev.Serial
                Log "  $($dev.Hostname) -> $($r.msg.line)"
            } catch { Log "  $($dev.Hostname) - $($_.Exception.Message)" }
        }
        UI { $fetchLock.Busy = $false; $fetchLock.Name = '' }
        Log "Sync requests sent."
    })
    [void]$ps.BeginInvoke()
})

# ── Set HA priority ──────────────────────────────────────────
function Set-HAPriority([string]$priority) {
    $sel = @($script:DisplayColl | Where-Object Selected)
    if ($sel.Count -eq 0) { Write-Log "No devices selected."; return }
    $names = ($sel | ForEach-Object { $_.Hostname }) -join ', '
    $impact = switch ($priority) {
        '70'  { 'Force to PRIMARY (priority 70). This WILL trigger an HA failover TO this peer.' }
        '90'  { 'Set normal PRIMARY priority (90).' }
        '110' { 'Set normal SECONDARY priority (110).' }
        '130' { 'Force to SECONDARY (priority 130). This WILL trigger an HA failover AWAY from this peer.' }
        default { "Set HA device-priority to $priority." }
    }
    if (-not (Confirm-Impact "HA Priority $priority" "$impact`n`nDevices ($($sel.Count)): $names`n`nChanges HA election config (preemptive=yes) on each selected firewall. Forcing priority can cause an immediate failover and a brief traffic disruption.")) { return }
    if (-not (Begin-Fetch "HA Priority $priority")) { return }
    $preemptive = 'yes'  # Always preemptive — never flip back to 'no' regardless of priority.
    Write-Log "Setting HA priority=$priority preemptive=$preemptive on $($sel.Count) device(s)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('sel',$sel)
    $rs.SessionStateProxy.SetVariable('priority',$priority)
    $rs.SessionStateProxy.SetVariable('preemptive',$preemptive)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b) { $Window.Dispatcher.Invoke($b, 'Normal') }
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
        UI { $fetchLock.Busy = $false; $fetchLock.Name = '' }
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
    $confirm = [System.Windows.MessageBox]::Show("Install PAN-OS $ver on $($sel.Count) selected device(s)?`n`nThis stages and installs the image but does NOT reboot — each device keeps running its current version until you reboot it. Best practice: install + reboot the PASSIVE peer first, verify, then the active peer. Continue?","Confirm Install","YesNo","Warning")
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
    # Mark devices as Rebooting in the MAIN scope before kicking off the runspace.
    # Two things had to move out of the runspace:
    #   1. Start-RebootPoller — previously called via Dispatcher.Invoke from
    #      inside the reboot runspace, but the dispatched scriptblock still
    #      carries the runspace's lexical scope where Start-RebootPoller is
    #      undefined. Result: the call silently no-op'd and the auto-poller
    #      never ran.
    #   2. Marking PingStatus='Rebooting' — must happen before we start the
    #      poller so the poller's first sweep actually finds devices to ping.
    foreach ($dev in $sel) {
        $dev.PingStatus  = 'Rebooting'
        $dev.PingLatency = '-'
    }
    Start-RebootPoller
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
            } catch {
                Log "  $($dev.Hostname) - reboot failed: $($_.Exception.Message)"
                # Roll back the optimistic marker so the poller doesn't keep pinging this device.
                UI { $dev.PingStatus = ''; $dev.PingLatency = '' }
            }
        }
        UI { $btnReboot.IsEnabled = $true }
        Log "Reboot commands sent. Auto-poller will detect when devices come back UP."
    })
    [void]$ps.BeginInvoke()
})

# ── Fetch Licenses (direct REST per firewall) ────────────────
# Panorama refuses to proxy <show><license><info/></license></show> for managed
# devices — it returns status="error" code="17" "show -> license is unexpected".
# So we bypass pan-power entirely for licenses: connect direct to each firewall's
# management IP, keygen with the stored Panorama creds (same RADIUS/local user
# works on the FW), and issue the op-command via plain REST.
#
# Since this no longer goes through pan-power, we can parallelize via a
# RunspacePool — none of the HANDOFF §6.1 module-state issues apply.
function Invoke-LicenseFetch([object[]]$devs) {
    if (-not $devs -or $devs.Count -eq 0) { Write-Log "No devices selected for licenses."; return }
    if (-not $script:PanCred.User -or -not $script:PanCred.Pass) {
        Write-Log "Not connected — connect to Panorama first (same credentials are used to keygen on each FW)."
        return
    }
    if (-not (Begin-Fetch 'Licenses')) { return }
    foreach ($d in $devs) {
        $d.LicWildFire='-'; $d.LicDNS='-'; $d.LicURL='-'; $d.LicIoT='-'
        $d.LicThreat='-';   $d.LicSupport='-'; $d.LicHasAny=$false
    }
    $txtLicStatus.Text = "Fetching..."
    Write-Log "Fetching licenses (direct REST) for $($devs.Count) device(s)..."

    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('devs',$devs)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('writeTraceFn',${function:Write-Trace})
    $rs.SessionStateProxy.SetVariable('txtLicStatus',$txtLicStatus)
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
    $rs.SessionStateProxy.SetVariable('panUser',$script:PanCred.User)
    $rs.SessionStateProxy.SetVariable('panPass',$script:PanCred.Pass)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Add-Type -AssemblyName System.Web
        function Log($m)   { & $writeLogFn $m }
        function Trace($m) { & $writeTraceFn $m 'License' }
        # Save the previous global cert callback so we restore it on exit and
        # don't leave pan-power's TLS in a broken state. Use the precompiled
        # SSLAcceptAll method (set up at script load), NEVER a PS scriptblock.
        $prevSslCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [SSLAcceptAll]::Callback
        Trace "Worker booted. SecurityProtocol=$([System.Net.ServicePointManager]::SecurityProtocol). Saved prev SSL callback."
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        function Get-Cell([string]$expires, [string]$expired) {
            if (-not $expires -and -not $expired) { return '-' }
            if ($expired -eq 'yes') { return "EXPIRED ($expires)" }
            if ($expires -eq 'Never' -or $expires -eq '') { return 'Active' }
            return $expires
        }
        # Convert an "expires" string to a sortable DateTime. Used to merge
        # regular + Advanced variants of the same feature (WildFire vs Advanced
        # WildFire, URL Filtering vs Advanced URL Filtering, etc.) — we keep
        # the one with the latest expiry. Never -> MaxValue so it always wins;
        # unparseable/empty -> MinValue so it always loses.
        function Get-ExpirySort([string]$expires) {
            if ([string]::IsNullOrWhiteSpace($expires)) { return [DateTime]::MinValue }
            if ($expires -eq 'Never') { return [DateTime]::MaxValue }
            $dt = [DateTime]::MinValue
            if ([DateTime]::TryParse($expires, [System.Globalization.CultureInfo]::InvariantCulture,
                                     [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dt)) {
                return $dt
            }
            return [DateTime]::MinValue
        }

        # Per-firewall worker. Runs in a RunspacePool slot, no pan-power.
        # Returns structured diag so the parent can dump everything to the trace file.
        $worker = {
            param($fwIp, $user, $pass)
            $diag = [PSCustomObject]@{
                IP=$fwIp; TcpReachable=$null; KeygenStatus=$null; KeygenError=$null
                LicenseStatus=$null; LicenseError=$null; ApiKeyLen=0; EntryCount=0
                Success=$false; Error=$null; Entries=$null; RawResponse=$null
            }
            try {
                # 1. TCP probe so we know whether the firewall's mgmt is reachable at all.
                try {
                    $tcp = New-Object System.Net.Sockets.TcpClient
                    $iar = $tcp.BeginConnect($fwIp, 443, $null, $null)
                    if ($iar.AsyncWaitHandle.WaitOne(3000, $false)) {
                        try { $tcp.EndConnect($iar); $diag.TcpReachable = $true } catch { $diag.TcpReachable = $false }
                    } else { $diag.TcpReachable = $false }
                    try { $tcp.Close() } catch {}
                } catch { $diag.TcpReachable = $false }
                if (-not $diag.TcpReachable) {
                    $diag.Error = 'TCP 443 not reachable from this workstation (firewall mgmt IP unreachable - check routing/ACLs)'
                    return $diag
                }
                # Cert callback is set by the parent License runspace globally to
                # [SSLAcceptAll]::Callback (compiled method, not a scriptblock).
                # Statics persist process-wide so we just use it as-is here.
                Add-Type -AssemblyName System.Web
                $userEnc = [System.Web.HttpUtility]::UrlEncode($user)
                $passEnc = [System.Web.HttpUtility]::UrlEncode($pass)
                # Concat instead of interpolated "$user=" — keeps PowerShell's parser happy.
                $kUri = 'https://' + $fwIp + '/api/?type=keygen&user=' + $userEnc + '&password=' + $passEnc
                try {
                    $k = Invoke-RestMethod -Uri $kUri -Method GET -TimeoutSec 20 -ErrorAction Stop
                    $diag.KeygenStatus = [string]$k.response.status
                } catch {
                    $diag.KeygenError = "$($_.Exception.GetType().Name): $($_.Exception.Message)"
                    if ($_.Exception.InnerException) {
                        $diag.KeygenError += " || inner: $($_.Exception.InnerException.GetType().Name): $($_.Exception.InnerException.Message)"
                    }
                    $diag.Error = 'keygen failed - ' + $diag.KeygenError
                    return $diag
                }
                $apikey = [string]$k.response.result.key
                $diag.ApiKeyLen = $apikey.Length
                if (-not $apikey) { $diag.Error = 'keygen returned no key'; return $diag }
                # PAN-OS XML API: license info is a REQUEST-family op, not a show-family
                # one. "<show><license/></show>" returns status=error "show -> license is
                # unexpected" because there's no <license> node under <show>. Per the
                # official docs the correct form is <request><license><info/></license></request>.
                $cmd    = [System.Web.HttpUtility]::UrlEncode('<request><license><info/></license></request>')
                $keyEnc = [System.Web.HttpUtility]::UrlEncode($apikey)
                $lUri = 'https://' + $fwIp + '/api/?type=op&cmd=' + $cmd + '&key=' + $keyEnc
                try {
                    $l = Invoke-RestMethod -Uri $lUri -Method GET -TimeoutSec 20 -ErrorAction Stop
                    $diag.LicenseStatus = [string]$l.response.status
                } catch {
                    $diag.LicenseError = "$($_.Exception.GetType().Name): $($_.Exception.Message)"
                    $diag.Error = 'license query failed - ' + $diag.LicenseError
                    return $diag
                }
                # Capture the raw response (truncated) for tracing regardless of status.
                try {
                    $ox = [string]$l.response.OuterXml
                    if ($ox) { $diag.RawResponse = $ox.Substring(0, [Math]::Min(800, $ox.Length)) }
                } catch {}
                if ($l.response.status -ne 'success') {
                    # Extract the human-readable message robustly. PAN-OS error responses
                    # use shapes like <msg><line>text</line></msg> or <msg>text</msg> or
                    # <msg><line><![CDATA[text]]></line></msg>. [string] on an XmlElement
                    # returns the type name, never the text — must use InnerText.
                    $msg = ''
                    try {
                        $m = $l.response.msg
                        if ($null -ne $m) {
                            if ($m -is [System.Xml.XmlElement]) { $msg = $m.InnerText }
                            else { $msg = [string]$m }
                        }
                    } catch {}
                    if (-not $msg) {
                        try { $msg = [string]$l.response.result } catch {}
                    }
                    $diag.Error = "license status=$($l.response.status) msg=$msg"
                    return $diag
                }
                $entries = @($l.response.result.licenses.entry | Where-Object { $_ })
                $diag.EntryCount = $entries.Count
                $diag.Entries    = $entries
                $diag.Success    = $true
                return $diag
            } catch {
                $diag.Error = "outer: $($_.Exception.GetType().Name): $($_.Exception.Message)"
                return $diag
            }
        }

        $pool = [runspacefactory]::CreateRunspacePool(1, 8)
        $pool.ApartmentState = 'STA'
        $pool.Open()
        $jobs = New-Object 'System.Collections.Generic.List[object]'
        foreach ($dev in $devs) {
            if (-not $dev.IPAddress) {
                Log "  $($dev.Hostname) - no IP from Panorama, skipping"
                continue
            }
            $p = [powershell]::Create()
            $p.RunspacePool = $pool
            [void]$p.AddScript($worker).AddArgument($dev.IPAddress).AddArgument($panUser).AddArgument($panPass)
            $h = $p.BeginInvoke()
            $jobs.Add([PSCustomObject]@{ Dev=$dev; PS=$p; Handle=$h })
        }

        $ok = 0; $unreachable = 0
        foreach ($j in $jobs) {
            try {
                $r = $j.PS.EndInvoke($j.Handle)
                $result = if ($r -and $r.Count -gt 0) { $r[0] } else { $null }
                # Trace every device's full diag — this is the data we need to read
                # back from PANManager-debug.log to diagnose anything that goes wrong.
                if ($result) {
                    Trace ("[{0}] ip={1} tcp={2} keygen={3} apikey_len={4} lic={5} entries={6} ok={7} err={8}" -f `
                        $j.Dev.Hostname, $result.IP, $result.TcpReachable, $result.KeygenStatus,
                        $result.ApiKeyLen, $result.LicenseStatus, $result.EntryCount, $result.Success, $result.Error)
                    if ($result.RawResponse) {
                        Trace ("[{0}] raw response: {1}" -f $j.Dev.Hostname, $result.RawResponse)
                    }
                } else {
                    Trace "[$($j.Dev.Hostname)] no result from worker"
                }
                if ($result -and $result.Success) {
                    # Each cell can be claimed by multiple license features (e.g.
                    # "WildFire License" + "Advanced WildFire License"). Collect every
                    # candidate per cell, then pick the one with the latest expiry —
                    # which naturally implements "not-expired beats expired, later
                    # expiry beats sooner, most-recently-expired beats earlier-expired".
                    $cands = @{ WF=@(); DNS=@(); URL=@(); IoT=@(); Threat=@(); Support=@() }
                    $unmatched = New-Object 'System.Collections.Generic.List[string]'
                    foreach ($e in @($result.Entries)) {
                        $feat    = [string]$e.feature
                        $expires = [string]$e.expires
                        $expired = [string]$e.expired
                        $cand = [PSCustomObject]@{
                            Feat = $feat
                            Sort = Get-ExpirySort $expires
                            Val  = Get-Cell $expires $expired
                        }
                        if     ($feat -match '(?i)wildfire')                                { $cands.WF      += $cand }
                        elseif ($feat -match '(?i)dns\s*security|dns-security')             { $cands.DNS     += $cand }
                        elseif ($feat -match '(?i)url\s*filt|pan-?db')                      { $cands.URL     += $cand }
                        elseif ($feat -match '(?i)iot|device\s*insights|advanced\s*device') { $cands.IoT     += $cand }
                        elseif ($feat -match '(?i)threat\s*prevention|advanced\s*threat')   { $cands.Threat  += $cand }
                        # Support tier: PAN-OS labels these as "Premium" or "Standard" with
                        # no literal "support" string. Match the standalone tier name OR any
                        # feature whose name contains "support".
                        elseif ($feat -match '(?i)^(premium|standard)(\s+(partner\s+)?support)?$|support|care') {
                            $cands.Support += $cand
                        }
                        else { $unmatched.Add($feat) }
                    }
                    if ($unmatched.Count -gt 0) {
                        Trace "[$($j.Dev.Hostname)] unmatched license features (not in any cell): $($unmatched -join ' | ')"
                    }
                    $cells = @{ WF='-'; DNS='-'; URL='-'; IoT='-'; Threat='-'; Support='-' }
                    foreach ($key in @('WF','DNS','URL','IoT','Threat','Support')) {
                        $list = @($cands[$key])
                        if ($list.Count -eq 0) { continue }
                        # Sort descending by expiry; the head is the "best" license.
                        $best = $list | Sort-Object Sort -Descending | Select-Object -First 1
                        $cells[$key] = $best.Val
                        if ($list.Count -gt 1) {
                            $picked = $best.Feat
                            $others = ($list | Where-Object { $_ -ne $best } | ForEach-Object { $_.Feat }) -join ', '
                            Trace "[$($j.Dev.Hostname)] $key has $($list.Count) variants -> picked '$picked' over: $others"
                        }
                    }
                    $dev = $j.Dev
                    UI {
                        $dev.LicWildFire=$cells.WF; $dev.LicDNS=$cells.DNS; $dev.LicURL=$cells.URL
                        $dev.LicIoT=$cells.IoT; $dev.LicThreat=$cells.Threat; $dev.LicSupport=$cells.Support
                        $dev.LicHasAny=$true
                    }
                    $ok++
                    Log "  $($j.Dev.Hostname) - $($result.EntryCount) feature(s)"
                } else {
                    if ($result -and $result.TcpReachable -eq $false) { $unreachable++ }
                    $err = if ($result) { $result.Error } else { 'no result' }
                    Log "  $($j.Dev.Hostname) - $err"
                }
            } catch {
                Log "  $($j.Dev.Hostname) - worker error: $($_.Exception.Message)"
                Trace "[$($j.Dev.Hostname)] EndInvoke threw: $($_.Exception)"
            } finally {
                try { $j.PS.Dispose() } catch {}
            }
        }
        if ($unreachable -gt 0) {
            Log "  NOTE: $unreachable firewall(s) had no TCP route to mgmt IP:443 from this workstation."
            Log "  Direct REST to firewall mgmt won't work. Check your network path / mgmt ACLs."
        }
        # Restore the previous cert callback so subsequent pan-power calls
        # (User-ID/ARP/Locks/EDLs/Content/etc.) see the same TLS state they had
        # before this fetch ran.
        try {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $prevSslCallback
            Trace "Restored previous SSL callback."
        } catch {
            Trace "Failed to restore SSL callback: $($_.Exception.Message)"
        }
        try { $pool.Close(); $pool.Dispose() } catch {}

        UI {
            $txtLicStatus.Text = "Matrix populated for $ok / $($devs.Count) device(s)"
            $fetchLock.Busy = $false; $fetchLock.Name = ''
        }
        Log "Licenses fetch complete: $ok / $($devs.Count) device(s)."
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
    if (-not (Begin-Fetch 'User-ID')) { return }
    $txtUserIDStatus.Text = "Fetching..."
    Write-Log "Checking User-ID on $($devs.Count) device(s)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('devs',$devs)
    $rs.SessionStateProxy.SetVariable('coll',$script:ColUserID)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtUserIDStatus)
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
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
        UI {
            $txtStatus.Text = "Done - $ok / $($devs.Count) device(s)"
            $fetchLock.Busy = $false; $fetchLock.Name = ''
        }
        Log "User-ID check complete."
    })
    [void]$ps.BeginInvoke()
}
$btnFetchUserID.Add_Click({    Invoke-UserIDFetch @($script:DisplayColl | Where-Object Selected) })
$btnFetchUserIDAll.Add_Click({ Invoke-UserIDFetch @($script:DisplayColl) })
$btnExportUserID.Add_Click({   Export-CollToCSV $script:ColUserID 'userid' })

# ── User-ID Resync helpers ────────────────────────────────────
# debug user-id refresh group-mapping all
#   → forces an LDAP refresh of all group-mapping configs on the firewall
# debug user-id cloud-identity-engine resync
#   → forces a resync with the CIE cloud agent (Prisma Access / CDSS path)
# Both commands return an op job; we fire-and-forget per device and log.
function Invoke-UserIDResync([object[]]$devs, [string]$kind) {
    if (-not $devs -or $devs.Count -eq 0) { Write-Log "No devices selected for User-ID resync."; return }
    $cmd = ''
    $label = ''
    switch ($kind) {
        'groups' {
            $cmd   = "<debug><user-id><refresh><group-mapping><all/></group-mapping></refresh></user-id></debug>"
            $label = "Resync Groups"
        }
        'cie' {
            $cmd   = "<debug><user-id><cloud-identity-engine><resync/></cloud-identity-engine></user-id></debug>"
            $label = "Resync CIE"
        }
        default { Write-Log "Unknown resync kind '$kind'."; return }
    }
    $msg = "$label on $($devs.Count) selected device(s)?"
    if ([System.Windows.MessageBox]::Show($msg, "Confirm $label", "YesNo", "Question") -ne 'Yes') { return }
    if (-not (Begin-Fetch $label)) { return }
    $txtUserIDStatus.Text = "$label..."
    Write-Log "$label on $($devs.Count) device(s)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('devs',$devs)
    $rs.SessionStateProxy.SetVariable('cmd',$cmd)
    $rs.SessionStateProxy.SetVariable('label',$label)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtUserIDStatus)
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        $ok = 0
        foreach ($dev in $devs) {
            try {
                $resp = Invoke-PANOperation -SkipCertificateCheck -Command $cmd -Target $dev.Serial
                $st = [string]$resp.status
                if ($st -eq 'success') { $ok++; Log "  $($dev.Hostname) - $label OK" }
                else { Log "  $($dev.Hostname) - $label status=$st" }
            } catch { Log "  $($dev.Hostname) - $label error: $($_.Exception.Message)" }
        }
        UI {
            $txtStatus.Text = "$label - $ok / $($devs.Count) OK"
            $fetchLock.Busy = $false; $fetchLock.Name = ''
        }
        Log "$label complete: $ok / $($devs.Count) device(s)."
    })
    [void]$ps.BeginInvoke()
}
$btnResyncGroups.Add_Click({ Invoke-UserIDResync @($script:DisplayColl | Where-Object Selected) 'groups' })
$btnResyncCIE.Add_Click({    Invoke-UserIDResync @($script:DisplayColl | Where-Object Selected) 'cie' })

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
    if (-not (Begin-Fetch 'ARP')) { return }
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
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
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
        UI {
            $txtStatus.Text = "Done - $total entries from $($devs.Count) device(s)"
            $fetchLock.Busy = $false; $fetchLock.Name = ''
        }
        Log "ARP fetch complete: $total entries."
    })
    [void]$ps.BeginInvoke()
}
$btnFetchARP.Add_Click({         Invoke-ARPFetch @($script:DisplayColl | Where-Object Selected) })
$btnFetchARPAll.Add_Click({      Invoke-ARPFetch @($script:DisplayColl) })
$btnExportARP.Add_Click({        Export-CollToCSV $script:ColARPAll 'arp' })
$txtARPFilter.Add_TextChanged({  Update-ARPFilter })
$btnARPClearFilter.Add_Click({   $txtARPFilter.Text = '' })

# Clear ALL ARP entries on each selected firewall.
# <clear><arp><entry-all/></arp></clear>
function Invoke-ARPClear([object[]]$devs) {
    if (-not $devs -or $devs.Count -eq 0) { Write-Log "No devices selected for ARP clear."; return }
    $msg = "Clear ALL ARP entries on $($devs.Count) selected device(s)?`n`nThe firewall will re-learn its ARP table from live traffic."
    if ([System.Windows.MessageBox]::Show($msg, "Confirm Clear ARP", "YesNo", "Warning") -ne 'Yes') { return }
    if (-not (Begin-Fetch 'ARP Clear')) { return }
    $txtARPStatus.Text = "Clearing..."
    Write-Log "Clearing ARP on $($devs.Count) device(s)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('devs',$devs)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtARPStatus)
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        $ok = 0
        foreach ($dev in $devs) {
            try {
                $resp = Invoke-PANOperation -SkipCertificateCheck `
                            -Command "<clear><arp><entry-all/></arp></clear>" `
                            -Target $dev.Serial
                $st = [string]$resp.status
                if ($st -eq 'success') { $ok++; Log "  $($dev.Hostname) - ARP cleared" }
                else { Log "  $($dev.Hostname) - clear status=$st" }
            } catch { Log "  $($dev.Hostname) - clear error: $($_.Exception.Message)" }
        }
        UI {
            $txtStatus.Text = "Cleared - $ok / $($devs.Count) device(s)"
            $fetchLock.Busy = $false; $fetchLock.Name = ''
        }
        Log "ARP clear complete: $ok / $($devs.Count) device(s)."
    })
    [void]$ps.BeginInvoke()
}
$btnClearARP.Add_Click({ Invoke-ARPClear @($script:DisplayColl | Where-Object Selected) })

# ── IPsec ────────────────────────────────────────────────────
# Field names vary wildly across PAN-OS versions. Try every known name for
# each field and pick the first non-empty. Devices with zero tunnels are
# skipped (no empty header rows in the grid).
function Invoke-IPsecFetch([object[]]$devs) {
    if (-not $devs -or $devs.Count -eq 0) { Write-Log "No devices selected for IPsec."; return }
    if (-not (Begin-Fetch 'IPsec')) { return }
    $txtIPsecStatus.Text = "Fetching..."
    Write-Log "Fetching IPsec SAs from $($devs.Count) device(s)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('devs',$devs)
    $rs.SessionStateProxy.SetVariable('coll',$script:ColIPsec)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtIPsecStatus)
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        # Pull the first non-empty value of any candidate property from an XmlElement.
        function GetProp($obj, [string[]]$names) {
            foreach ($n in $names) {
                try {
                    $v = $obj.$n
                    if ($null -ne $v -and ([string]$v).Trim() -ne '') { return [string]$v }
                } catch {}
            }
            return ''
        }
        UI { $coll.Clear() }
        $total = 0; $withTunnels = 0
        foreach ($dev in $devs) {
            try {
                $resp = Invoke-PANOperation -SkipCertificateCheck `
                            -Command "<show><vpn><ipsec-sa/></vpn></show>" `
                            -Target $dev.Serial
                if ($resp.status -ne 'success') { Log "  $($dev.Hostname) - status=$($resp.status)"; continue }
                # Entries can be at .result.entries.entry or .result.entry; some PAN-OS
                # versions return CDATA which gets exposed as text-only — skip those.
                $entries = @()
                try { $entries = @($resp.result.entries.entry | Where-Object { $_ -is [System.Xml.XmlElement] }) } catch {}
                if ($entries.Count -eq 0) {
                    try { $entries = @($resp.result.entry | Where-Object { $_ -is [System.Xml.XmlElement] }) } catch {}
                }
                if ($entries.Count -eq 0) { continue }   # no tunnels — skip
                if ($withTunnels -eq 0) { try { Log "[IPsec DIAG] $($dev.Hostname) first SA XML: $([string]$entries[0].OuterXml)" } catch {} }

                $rows = New-Object 'System.Collections.Generic.List[object]'
                foreach ($e in $entries) {
                    $name  = GetProp $e @('name','tnn-name','tunnel-name','tunnel-id')
                    $peer  = GetProp $e @('peerip','peer-ip','peer','gw','gateway-ip')
                    $gwn   = GetProp $e @('gw-name','gateway-name','gateway','gwname')
                    $state = GetProp $e @('state','mon-stat','status')
                    $enc   = GetProp $e @('esp-encryption','enc','algo','algorithm')
                    $auth  = GetProp $e @('esp-auth','hash','auth')
                    $alg   = ("$enc $auth").Trim()
                    if (-not $name -and -not $peer -and -not $gwn -and -not $alg) { continue }
                    $rows.Add([PSCustomObject]@{
                        Hostname  = $dev.Hostname
                        Serial    = $dev.Serial    # not bound to a grid column; used by Clear Tunnels
                        Name      = $name
                        Peer      = $peer
                        GwName    = $gwn
                        State     = $state
                        Algorithm = $alg
                    })
                }
                if ($rows.Count -eq 0) { continue }
                UI { foreach ($r in $rows) { $coll.Add($r) } }
                $total       += $rows.Count
                $withTunnels += 1
                Log "  $($dev.Hostname) - $($rows.Count) IPsec SA(s)"
            } catch { Log "  $($dev.Hostname) - $($_.Exception.Message)" }
        }
        UI {
            $txtStatus.Text = "Done - $total SA(s) across $withTunnels / $($devs.Count) device(s)"
            $fetchLock.Busy = $false; $fetchLock.Name = ''
        }
        Log "IPsec fetch complete: $total SA(s) on $withTunnels device(s)."
    })
    [void]$ps.BeginInvoke()
}
$btnFetchIPsec.Add_Click({    Invoke-IPsecFetch @($script:DisplayColl | Where-Object Selected) })
$btnFetchIPsecAll.Add_Click({ Invoke-IPsecFetch @($script:DisplayColl) })
$btnExportIPsec.Add_Click({   Export-CollToCSV $script:ColIPsec 'ipsec' })

# Clear the IPsec SAs currently selected in dgIPsec. Each row carries the
# firewall Serial (added in Invoke-IPsecFetch) so we can target the right
# device. PAN-OS command:
#   <clear><vpn><ipsec-sa><tunnel>NAME</tunnel></ipsec-sa></vpn></clear>
function Invoke-IPsecClear {
    $sel = @($dgIPsec.SelectedItems)
    if ($sel.Count -eq 0) {
        [System.Windows.MessageBox]::Show("Select one or more tunnel rows in the grid first.", "No selection", "OK", "Information") | Out-Null
        return
    }
    $names = ($sel | ForEach-Object { "$($_.Hostname): $($_.Name)" }) -join "`n  "
    $msg = "Clear $($sel.Count) IPsec tunnel(s)?`n`n  $names`n`nThis tears down the SA(s); the tunnel will renegotiate on next traffic."
    if ([System.Windows.MessageBox]::Show($msg, "Confirm Clear Tunnels", "YesNo", "Warning") -ne 'Yes') { return }
    if (-not (Begin-Fetch 'IPsec Clear')) { return }
    $txtIPsecStatus.Text = "Clearing..."
    Write-Log "Clearing $($sel.Count) IPsec tunnel(s)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('rows',$sel)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtIPsecStatus)
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        $ok = 0
        foreach ($r in $rows) {
            $serial = [string]$r.Serial
            $name   = [string]$r.Name
            if (-not $serial -or -not $name) { Log "  skipping row with missing serial/name"; continue }
            try {
                $resp = Invoke-PANOperation -SkipCertificateCheck `
                            -Command ("<clear><vpn><ipsec-sa><tunnel>" + $name + "</tunnel></ipsec-sa></vpn></clear>") `
                            -Target $serial
                $st = [string]$resp.status
                if ($st -eq 'success') { $ok++; Log "  $($r.Hostname) - cleared $name" }
                else { Log "  $($r.Hostname) - $name status=$st" }
            } catch { Log "  $($r.Hostname) - $name error: $($_.Exception.Message)" }
        }
        UI {
            $txtStatus.Text = "Cleared $ok / $($rows.Count) tunnel(s)"
            $fetchLock.Busy = $false; $fetchLock.Name = ''
        }
        Log "IPsec clear complete: $ok / $($rows.Count) tunnel(s)."
    })
    [void]$ps.BeginInvoke()
}
$btnClearIPsec.Add_Click({ Invoke-IPsecClear })

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
    if (-not (Begin-Fetch 'Routes')) { return }
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
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
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
        UI {
            $txtStatus.Text = "Done - $total routes from $($devs.Count) device(s)"
            $fetchLock.Busy = $false; $fetchLock.Name = ''
        }
        Log "Routes fetch complete: $total routes."
    })
    [void]$ps.BeginInvoke()
}
$btnFetchRoutes.Add_Click({       Invoke-RoutesFetch @($script:DisplayColl | Where-Object Selected) })
$btnFetchRoutesAll.Add_Click({    Invoke-RoutesFetch @($script:DisplayColl) })
$btnExportRoutes.Add_Click({      Export-CollToCSV $script:ColRoutesAll 'routes' })
$txtRouteFilter.Add_TextChanged({ Update-RoutesFilter })
$btnRouteClearFilter.Add_Click({  $txtRouteFilter.Text = '' })

# ── Interface IPs ────────────────────────────────────────────
# Pulls every configured interface IP (show interface all -> ifnet) from each
# selected firewall, with derived Public/Private scope and region (from hostname).
# Scope = static combo; Zone/Region/Iface-IP = regex text filters (same idiom as ARP).
function Update-IfFilter {
    try {
        $scopeItem = $cbIfScope.SelectedItem
        $scope = if ($scopeItem -and $scopeItem.Content) { [string]$scopeItem.Content } else { '(All)' }
        $arpItem = $cbIfArp.SelectedItem
        $arp = if ($arpItem -and $arpItem.Content) { [string]$arpItem.Content } else { '(All)' }
        $zone   = $txtIfZone.Text.Trim()
        $region = $txtIfRegion.Text.Trim()
        $f      = $txtIfFilter.Text.Trim()
        $script:ColIf.Clear()
        foreach ($r in $script:ColIfAll) {
            try {
                if ($scope  -ne '(All)' -and $r.Scope  -ne $scope)  { continue }
                if ($zone   -ne ''      -and $r.Zone   -notmatch $zone)   { continue }
                if ($region -ne ''      -and $r.Region -notmatch $region) { continue }
                if ($f      -ne ''      -and -not (($r.Interface -match $f) -or ($r.IP -match $f))) { continue }
                if ($arp -eq 'Has valid ARPs' -and [int]$r.ARPCount -le 0) { continue }
                if ($arp -eq 'No valid ARPs'  -and [int]$r.ARPCount -ne 0) { continue }
                $script:ColIf.Add($r)
            } catch {}
        }
        $txtIfStatus.Text = "Showing $($script:ColIf.Count) of $($script:ColIfAll.Count) IPs"
    } catch {}
}
function Invoke-IfFetch([object[]]$devs) {
    if (-not $devs -or $devs.Count -eq 0) { Write-Log "No devices selected for interfaces."; return }
    if (-not (Begin-Fetch 'Interfaces')) { return }
    $txtIfStatus.Text = "Fetching..."
    Write-Log "Fetching interface IPs from $($devs.Count) device(s)..."
    $script:ColIfAll.Clear(); $script:ColIf.Clear()
    # Reset filters to defaults so the fresh result shows unfiltered.
    $cbIfScope.SelectedIndex = 0; $cbIfArp.SelectedIndex = 0
    $txtIfZone.Text = ''; $txtIfRegion.Text = ''; $txtIfFilter.Text = ''
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('devs',$devs)
    $rs.SessionStateProxy.SetVariable('allList',$script:ColIfAll)
    $rs.SessionStateProxy.SetVariable('coll',$script:ColIf)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtIfStatus)
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        # Classify an address (CIDR or bare) as Public/Private per RFC1918 + link-local.
        function Get-IPScope([string]$cidr) {
            $ip = (([string]$cidr) -split '/')[0].Trim()
            if ($ip -eq '') { return '' }
            if ($ip.Contains(':')) {
                $l = $ip.ToLower()
                if ($l.StartsWith('fe80') -or $l.StartsWith('fc') -or $l.StartsWith('fd') -or $l -eq '::1') { return 'Private' }
                return 'Public'
            }
            $o = $ip.Split('.')
            if ($o.Count -lt 4) { return '' }
            [int]$a = 0; [int]$b = 0
            if (-not [int]::TryParse($o[0],[ref]$a)) { return '' }
            [void][int]::TryParse($o[1],[ref]$b)
            if ($a -eq 10) { return 'Private' }
            if ($a -eq 172 -and $b -ge 16 -and $b -le 31) { return 'Private' }
            if ($a -eq 192 -and $b -eq 168) { return 'Private' }
            if ($a -eq 169 -and $b -eq 254) { return 'Private' }
            return 'Public'
        }
        # Derive region token from hostname (same tokens as the main Region filter).
        function Get-Region([string]$h) {
            foreach ($t in @('US','EU','UK','AU','NZ','CH','MFG','SHP')) { if ($h -match $t) { return $t } }
            return ''
        }
        # A "valid" ARP MAC = a real unicast hardware address (not incomplete / all-zero).
        function Is-RealMac([string]$mac) {
            $m = ([string]$mac).Trim()
            if ($m -eq '') { return $false }
            if ($m -match 'incomplete') { return $false }
            if ($m -eq '00:00:00:00:00:00') { return $false }
            if ($m -notmatch '^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$') { return $false }
            return $true
        }
        $total = 0; $first = $true
        foreach ($dev in $devs) {
            try {
                $resp = Invoke-PANOperation -SkipCertificateCheck `
                            -Command "<show><interface>all</interface></show>" `
                            -Target $dev.Serial
                if ($resp.status -ne 'success') { Log "  $($dev.Hostname) - status=$($resp.status)"; continue }
                $entries = @($resp.result.ifnet.entry)
                if ($first) { try { Log "[Iface DIAG] $($dev.Hostname) first ifnet XML: $([string]$entries[0].OuterXml)" } catch {}; $first = $false }
                $region = Get-Region $dev.Hostname
                # Pull the ARP table once and index VALID neighbour entries per interface,
                # so each interface row can show its count of other devices learned on it.
                $arpByIf = @{}
                try {
                    $arpResp = Invoke-PANOperation -SkipCertificateCheck `
                                   -Command "<show><arp><entry name='all'/></arp></show>" `
                                   -Target $dev.Serial
                    if ($arpResp.status -eq 'success') {
                        foreach ($ae in @($arpResp.result.entries.entry)) {
                            if ([string]$ae.status -eq 'i') { continue }     # skip incomplete
                            if (-not (Is-RealMac $ae.mac)) { continue }       # must be a real MAC
                            $aif = [string]$ae.interface
                            if (-not $aif) { continue }
                            if (-not $arpByIf.ContainsKey($aif)) { $arpByIf[$aif] = New-Object 'System.Collections.Generic.List[string]' }
                            $arpByIf[$aif].Add((([string]$ae.ip) -split '/')[0].Trim())
                        }
                    }
                } catch { Log "  $($dev.Hostname) - ARP fetch error: $($_.Exception.Message)" }
                $rows = New-Object 'System.Collections.Generic.List[object]'
                foreach ($e in $entries) {
                    $ips = New-Object 'System.Collections.Generic.List[string]'
                    foreach ($cand in @([string]$e.ip)) {
                        $v = $cand.Trim()
                        if ($v -and $v -ne 'N/A' -and ($ips -notcontains $v)) { [void]$ips.Add($v) }
                    }
                    if ($e.addr  -and $e.addr.member)  { foreach ($m in @($e.addr.member))  { $v=([string]$m).Trim(); if ($v -and $v -ne 'N/A' -and ($ips -notcontains $v)) { [void]$ips.Add($v) } } }
                    if ($e.addr6 -and $e.addr6.member) { foreach ($m in @($e.addr6.member)) { $v=([string]$m).Trim(); if ($v -and $v -ne 'N/A' -and ($ips -notcontains $v)) { [void]$ips.Add($v) } } }
                    if ($ips.Count -eq 0) { continue }
                    $vr = [string]$e.fwd
                    if ($vr -like 'vr:*') { $vr = $vr.Substring(3) } elseif ($vr -eq 'N/A') { $vr = '' }
                    $zone = [string]$e.zone; if ($zone -eq 'N/A') { $zone = '' }
                    # Count valid ARP neighbours on this interface, excluding the
                    # interface's own IP(s). (arpByIf already holds only real-MAC entries.)
                    $ownBare = @($ips | ForEach-Object { ($_ -split '/')[0].Trim() })
                    $arpCount = 0
                    $arpList = $arpByIf[[string]$e.name]
                    if ($arpList) { foreach ($aip in $arpList) { if ($ownBare -notcontains $aip) { $arpCount++ } } }
                    foreach ($ip in $ips) {
                        $rows.Add([PSCustomObject]@{
                            Hostname  = $dev.Hostname
                            Region    = $region
                            Interface = [string]$e.name
                            Zone      = $zone
                            IP        = $ip
                            Scope     = (Get-IPScope $ip)
                            ARPCount  = $arpCount
                            VR        = $vr
                            VSYS      = [string]$e.vsys
                            VLAN      = [string]$e.tag
                        })
                    }
                }
                UI {
                    foreach ($r in $rows) { $allList.Add($r); $coll.Add($r) }
                    $txtStatus.Text = "Fetched $($total + $rows.Count) IPs..."
                }
                $total += $rows.Count
                Log "  $($dev.Hostname) - $($rows.Count) interface IP(s)"
            } catch { Log "  $($dev.Hostname) - $($_.Exception.Message)" }
        }
        UI {
            $txtStatus.Text = "Done - $total IPs from $($devs.Count) device(s)"
            $fetchLock.Busy = $false; $fetchLock.Name = ''
        }
        Log "Interface IP fetch complete: $total IPs."
    })
    [void]$ps.BeginInvoke()
}
$btnFetchIf.Add_Click({       Invoke-IfFetch @($script:DisplayColl | Where-Object Selected) })
$btnFetchIfAll.Add_Click({    Invoke-IfFetch @($script:DisplayColl) })
$btnExportIf.Add_Click({      Export-CollToCSV $script:ColIfAll 'interface-ips' })
$cbIfScope.Add_SelectionChanged({ Update-IfFilter })
$cbIfArp.Add_SelectionChanged({   Update-IfFilter })
$txtIfZone.Add_TextChanged({   Update-IfFilter })
$txtIfRegion.Add_TextChanged({ Update-IfFilter })
$txtIfFilter.Add_TextChanged({ Update-IfFilter })
$btnIfClearFilter.Add_Click({  $cbIfScope.SelectedIndex = 0; $cbIfArp.SelectedIndex = 0; $txtIfZone.Text=''; $txtIfRegion.Text=''; $txtIfFilter.Text='' })

# ── Config Locks ─────────────────────────────────────────────
function Invoke-LocksFetch([object[]]$devs) {
    if (-not $devs -or $devs.Count -eq 0) { Write-Log "No devices selected for locks."; return }
    if (-not (Begin-Fetch 'Locks')) { return }
    $txtLocksStatus.Text = "Fetching..."
    Write-Log "Checking commit-locks on $($devs.Count) device(s)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('devs',$devs)
    $rs.SessionStateProxy.SetVariable('coll',$script:ColLocks)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtLocksStatus)
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
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
                # Entries with no admin name are placeholder rows ("commit-lock available")
                # from some PAN-OS versions, not actual locks. Filter them out so the count
                # reflects real locks only.
                $raw = @($resp.result.'commit-locks'.entry | Where-Object { $_ -is [System.Xml.XmlElement] })
                $real = @($raw | Where-Object {
                    $n = ''
                    try { $n = [string]$_.name } catch {}
                    $n.Trim() -ne ''
                })
                if ($real.Count -eq 0) { continue }
                $locked++
                $rows = New-Object 'System.Collections.Generic.List[object]'
                foreach ($e in $real) {
                    $rows.Add([PSCustomObject]@{
                        Hostname = $dev.Hostname
                        LockType = [string]$e.type
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
        UI {
            $txtStatus.Text = "Done - $totalLocks lock(s) on $locked / $($devs.Count) device(s)"
            $fetchLock.Busy = $false; $fetchLock.Name = ''
        }
        Log "Lock check complete: $totalLocks lock(s) on $locked device(s)."
    })
    [void]$ps.BeginInvoke()
}
function Invoke-LocksRemove([object[]]$devs) {
    if (-not $devs -or $devs.Count -eq 0) { Write-Log "No devices selected for lock removal."; return }
    $msg = "Remove ALL commit-locks on $($devs.Count) selected device(s)?`n`nThis reverts any uncommitted config changes on the device side."
    if ([System.Windows.MessageBox]::Show($msg, "Confirm Remove Locks", "YesNo", "Warning") -ne 'Yes') { return }
    if (-not (Begin-Fetch 'Lock Remove')) { return }
    $txtLocksStatus.Text = "Removing..."
    Write-Log "Removing locks on $($devs.Count) device(s)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('devs',$devs)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtLocksStatus)
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
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
        UI {
            $txtStatus.Text = "Removed $cleared lock(s)."
            $fetchLock.Busy = $false; $fetchLock.Name = ''
        }
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
    if (-not (Begin-Fetch 'EDLs')) { return }
    $txtEDLStatus.Text = "Loading EDL list..."
    Write-Log "Loading shared EDLs from Panorama..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('coll',$script:ColEDLs)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtEDLStatus)
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
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
                UI { $txtStatus.Text = "No shared EDLs found."; $fetchLock.Busy = $false; $fetchLock.Name = '' }
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
            UI { $txtStatus.Text = "Loaded $($rows.Count) EDL(s)."; $fetchLock.Busy = $false; $fetchLock.Name = '' }
            Log "Loaded $($rows.Count) shared EDL(s)."
        } catch {
            Log "EDL load failed: $($_.Exception.Message)"
            UI { $txtStatus.Text = "Load failed."; $fetchLock.Busy = $false; $fetchLock.Name = '' }
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
    if (-not (Begin-Fetch 'EDL Refresh')) { return }
    $txtEDLStatus.Text = "Refreshing..."
    Write-Log "Refreshing $($checked.Count) EDL(s) on $($devs.Count) device(s)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('edls',$checked)
    $rs.SessionStateProxy.SetVariable('devs',$devs)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtEDLStatus)
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
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
        UI {
            $txtStatus.Text = "Done - OK:$ok Fail:$fail"
            $fetchLock.Busy = $false; $fetchLock.Name = ''
        }
        Log "EDL refresh complete: OK=$ok Fail=$fail"
    })
    [void]$ps.BeginInvoke()
}
$btnFetchEDLs.Add_Click({   Invoke-EDLFetch })
$btnRefreshEDLs.Add_Click({ Invoke-EDLRefresh })
$btnSelAllEDLs.Add_Click({  foreach ($e in $script:ColEDLs) { $e.Selected = $true  } })
$btnSelNoneEDLs.Add_Click({ foreach ($e in $script:ColEDLs) { $e.Selected = $false } })

# ════════════════════════════════════════════════════════════
#  BATCH 2 — Content / System / Commits / GP-Users + actions
# ════════════════════════════════════════════════════════════

# ── Content versions matrix ──────────────────────────────────
function Invoke-ContentFetch([object[]]$devs) {
    if (-not $devs -or $devs.Count -eq 0) { Write-Log "No devices selected for content fetch."; return }
    if (-not (Begin-Fetch 'Content')) { return }
    $txtContentStatus.Text = "Fetching..."
    Write-Log "Fetching content versions for $($devs.Count) device(s)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('devs',$devs)
    $rs.SessionStateProxy.SetVariable('coll',$script:ColContent)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtContentStatus)
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        UI { $coll.Clear() }
        $ok = 0
        foreach ($dev in $devs) {
            try {
                $resp = Invoke-PANOperation -SkipCertificateCheck `
                            -Command "<show><system><info/></system></show>" -Target $dev.Serial
                $sys = $resp.result.system
                if (-not $sys) { Log "  $($dev.Hostname) - no system info"; continue }
                $row = [PSCustomObject]@{
                    Hostname  = $dev.Hostname
                    AppThreat = [string]$sys.'app-version'      # combined apps+threats since 8.0
                    AV        = [string]$sys.'av-version'
                    WildFire  = [string]$sys.'wildfire-version'
                    URLDB     = [string]$sys.'url-filtering-version'
                    GPData    = [string]$sys.'global-protect-datafile-version'
                    Uptime    = [string]$sys.uptime
                }
                UI { $coll.Add($row) }
                $ok++
                Log "  $($dev.Hostname) - app:$($row.AppThreat) av:$($row.AV) wf:$($row.WildFire)"
            } catch { Log "  $($dev.Hostname) - $($_.Exception.Message)" }
        }
        UI {
            $txtStatus.Text = "Done - $ok / $($devs.Count) device(s)"
            $fetchLock.Busy = $false; $fetchLock.Name = ''
        }
        Log "Content fetch complete."
    })
    [void]$ps.BeginInvoke()
}
$btnFetchContent.Add_Click({    Invoke-ContentFetch @($script:DisplayColl | Where-Object Selected) })
$btnFetchContentAll.Add_Click({ Invoke-ContentFetch @($script:DisplayColl) })
$btnExportContent.Add_Click({   Export-CollToCSV $script:ColContent 'content_versions' })

# Force a content (Apps+Threats) update on each selected firewall.
# Sequence per device:
#   1. <request><content><upgrade><check/></upgrade></content></request>
#   2. <request><content><upgrade><download><latest/></download></upgrade></content></request>
#      → returns a JobID; poll until FIN
#   3. <request><content><upgrade><install><version>latest</version><skip-content-validity-check>no</skip-content-validity-check></install></upgrade></content></request>
#      → returns a JobID; poll until FIN
# Job poll uses <show><jobs><id>N</id></jobs></show>.
function Invoke-ContentForceUpdate([object[]]$devs) {
    if (-not $devs -or $devs.Count -eq 0) { Write-Log "No devices selected for content force-update."; return }
    $msg = "Force content (Apps+Threats) update on $($devs.Count) device(s)?`n`nThis will check → download → install the latest content on each firewall. Can take several minutes per device. Devices already on the latest content will be no-ops."
    if ([System.Windows.MessageBox]::Show($msg, "Confirm Force Content Update", "YesNo", "Warning") -ne 'Yes') { return }
    if (-not (Begin-Fetch 'Content Force')) { return }
    $txtContentStatus.Text = "Updating..."
    Write-Log "Force content update on $($devs.Count) device(s)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('devs',$devs)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtContentStatus)
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }

        # Poll a PAN-OS job until it finishes (FIN) or times out.
        function Wait-Job($serial, [string]$jobId, [int]$timeoutSec = 600) {
            if (-not $jobId) { return $null }
            $deadline = (Get-Date).AddSeconds($timeoutSec)
            while ((Get-Date) -lt $deadline) {
                try {
                    $j = Invoke-PANOperation -SkipCertificateCheck `
                            -Command ("<show><jobs><id>" + $jobId + "</id></jobs></show>") `
                            -Target $serial
                    $job = $j.result.job
                    $st  = [string]$job.status
                    $res = [string]$job.result
                    $prog = [string]$job.progress
                    if ($st -eq 'FIN') { return $job }
                } catch { Log "    job $jobId poll error: $($_.Exception.Message)" }
                Start-Sleep -Seconds 5
            }
            Log "    job $jobId TIMEOUT after ${timeoutSec}s"
            return $null
        }

        $okDownload = 0; $okInstall = 0; $skipped = 0
        foreach ($dev in $devs) {
            try {
                Log "  $($dev.Hostname) - checking..."
                try {
                    [void](Invoke-PANOperation -SkipCertificateCheck `
                            -Command "<request><content><upgrade><check/></upgrade></content></request>" `
                            -Target $dev.Serial)
                } catch { Log "    check warning: $($_.Exception.Message)" }

                # Download latest
                Log "  $($dev.Hostname) - downloading..."
                $dlJobId = $null
                try {
                    $dl = Invoke-PANOperation -SkipCertificateCheck `
                            -Command "<request><content><upgrade><download><latest/></download></upgrade></content></request>" `
                            -Target $dev.Serial
                    # JobID can be at .result.job or in CDATA - handle both
                    try { $dlJobId = [string]$dl.result.job } catch {}
                    if (-not $dlJobId) {
                        $txt = [string]($dl.InnerText)
                        $m = [regex]::Match($txt, 'job\s*id[\s:=]*([0-9]+)','IgnoreCase')
                        if ($m.Success) { $dlJobId = $m.Groups[1].Value }
                    }
                } catch {
                    $errMsg = $_.Exception.Message
                    if ($errMsg -match 'already.*up.*to.*date|no.*update.*available') {
                        Log "  $($dev.Hostname) - already up to date, skipping"
                        $skipped++
                        continue
                    } else {
                        Log "  $($dev.Hostname) - download error: $errMsg"
                        continue
                    }
                }
                if ($dlJobId) {
                    $dlJob = Wait-Job $dev.Serial $dlJobId 900
                    if ($dlJob -and ([string]$dlJob.result -eq 'OK')) {
                        $okDownload++; Log "  $($dev.Hostname) - download OK (job $dlJobId)"
                    } else {
                        Log "  $($dev.Hostname) - download failed (job $dlJobId)"; continue
                    }
                } else {
                    Log "  $($dev.Hostname) - no download job id returned"
                }

                # Install latest
                Log "  $($dev.Hostname) - installing..."
                $insJobId = $null
                try {
                    $ins = Invoke-PANOperation -SkipCertificateCheck `
                            -Command "<request><content><upgrade><install><version>latest</version><skip-content-validity-check>no</skip-content-validity-check></install></upgrade></content></request>" `
                            -Target $dev.Serial
                    try { $insJobId = [string]$ins.result.job } catch {}
                    if (-not $insJobId) {
                        $txt = [string]($ins.InnerText)
                        $m = [regex]::Match($txt, 'job\s*id[\s:=]*([0-9]+)','IgnoreCase')
                        if ($m.Success) { $insJobId = $m.Groups[1].Value }
                    }
                } catch { Log "  $($dev.Hostname) - install error: $($_.Exception.Message)"; continue }
                if ($insJobId) {
                    $insJob = Wait-Job $dev.Serial $insJobId 900
                    if ($insJob -and ([string]$insJob.result -eq 'OK')) {
                        $okInstall++; Log "  $($dev.Hostname) - install OK (job $insJobId)"
                    } else {
                        Log "  $($dev.Hostname) - install failed (job $insJobId)"
                    }
                } else {
                    Log "  $($dev.Hostname) - no install job id returned"
                }
            } catch { Log "  $($dev.Hostname) - unexpected: $($_.Exception.Message)" }
        }
        UI {
            $txtStatus.Text = "Done - $okInstall installed, $okDownload downloaded, $skipped already current (of $($devs.Count))"
            $fetchLock.Busy = $false; $fetchLock.Name = ''
        }
        Log "Content force update complete: install=$okInstall download=$okDownload skipped=$skipped / $($devs.Count)."
    })
    [void]$ps.BeginInvoke()
}
$btnForceContent.Add_Click({ Invoke-ContentForceUpdate @($script:DisplayColl | Where-Object Selected) })

# ── Software image cleanup ───────────────────────────────────
# Lists locally-downloaded PAN-OS images per firewall and flags which are safe
# to delete: downloaded, NOT the running image, NOT a base/.0 maintenance release
# (e.g. 11.1.0, 10.2.0 — kept), and OLDER than the running version. Delete runs
# 'request system software delete version <ver>' (a write -> -Target serial).
function Update-SWFilter {
    try {
        $only = $cbSWDeletableOnly.IsChecked
        $script:ColSW.Clear()
        foreach ($r in $script:ColSWAll) {
            if ($only -and $r.Deletable -ne 'yes') { continue }
            $script:ColSW.Add($r)
        }
        $txtSWStatus.Text = "Showing $($script:ColSW.Count) of $($script:ColSWAll.Count) image(s)"
    } catch {}
}
function Invoke-SWFetch([object[]]$devs) {
    if (-not $devs -or $devs.Count -eq 0) { Write-Log "No devices selected for SW Cleanup."; return }
    if (-not (Begin-Fetch 'SW Cleanup')) { return }
    $txtSWStatus.Text = "Fetching..."
    Write-Log "Fetching software image inventory from $($devs.Count) device(s)..."
    $script:ColSWAll.Clear(); $script:ColSW.Clear()
    $btnDeleteSW.IsEnabled = $true
    $deletableOnly = [bool]$cbSWDeletableOnly.IsChecked
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('devs',$devs)
    $rs.SessionStateProxy.SetVariable('allList',$script:ColSWAll)
    $rs.SessionStateProxy.SetVariable('coll',$script:ColSW)
    $rs.SessionStateProxy.SetVariable('deletableOnly',$deletableOnly)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtSWStatus)
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        # "11.1.3-h2" -> [version]11.1.3.2 ; "10.2.4" -> 10.2.4.0
        function Parse-SWVer([string]$v) {
            $m = [regex]::Match([string]$v, '^(\d+)\.(\d+)\.(\d+)(?:-h(\d+))?')
            if (-not $m.Success) { return $null }
            $hf = if ($m.Groups[4].Success) { [int]$m.Groups[4].Value } else { 0 }
            return [version]::new([int]$m.Groups[1].Value, [int]$m.Groups[2].Value, [int]$m.Groups[3].Value, $hf)
        }
        # Base/.0 maintenance release (e.g. 11.1.0, 10.2.0) — kept, never flagged deletable.
        function Is-BaseRel([string]$v) {
            $m = [regex]::Match([string]$v, '^\d+\.\d+\.(\d+)')
            return ($m.Success -and [int]$m.Groups[1].Value -eq 0)
        }
        $total = 0; $first = $true
        foreach ($dev in $devs) {
            try {
                $r = Invoke-PANOperation -SkipCertificateCheck `
                        -Command "<request><system><software><info/></software></system></request>" `
                        -Target $dev.Serial
                if ($r.status -ne 'success') { Log "  $($dev.Hostname) - status=$($r.status)"; continue }
                $entries = @($r.result.'sw-updates'.versions.entry)
                if ($first) { try { Log "[SWClean DIAG] $($dev.Hostname) first version XML: $([string]$entries[0].OuterXml)" } catch {}; $first = $false }
                # Running version on this device
                $curVer = ''
                foreach ($e in $entries) { if (([string]$e.current) -eq 'yes') { $curVer = [string]$e.version; break } }
                $curParsed = Parse-SWVer $curVer
                $rows = New-Object 'System.Collections.Generic.List[object]'
                foreach ($e in $entries) {
                    $ver        = [string]$e.version
                    $downloaded = (([string]$e.downloaded) -eq 'yes')
                    $isCurrent  = (([string]$e.current) -eq 'yes')
                    # Only locally-present images are relevant for cleanup
                    if (-not $downloaded -and -not $isCurrent) { continue }
                    $base  = Is-BaseRel $ver
                    $vp    = Parse-SWVer $ver
                    $older = if ($vp -and $curParsed) { $vp -lt $curParsed } else { $false }
                    $deletable = ($downloaded -and -not $isCurrent -and -not $base -and $older)
                    $rows.Add([PSCustomObject]@{
                        Hostname   = $dev.Hostname
                        Serial     = $dev.Serial          # not a column; used by Delete
                        Version    = $ver
                        Running    = $(if ($isCurrent) { 'yes' } else { '' })
                        Downloaded = $(if ($downloaded) { 'yes' } else { 'no' })
                        Base       = $(if ($base) { 'yes' } else { 'no' })
                        Older      = $(if ($older) { 'yes' } else { 'no' })
                        Deletable  = $(if ($deletable) { 'yes' } else { 'no' })
                        Released   = [string]$e.'released-on'
                        Size       = [string]$e.size
                    })
                }
                UI {
                    foreach ($r2 in $rows) {
                        $allList.Add($r2)
                        if (-not $deletableOnly -or $r2.Deletable -eq 'yes') { $coll.Add($r2) }
                    }
                    $txtStatus.Text = "Showing $($coll.Count) of $($allList.Count) image(s)"
                }
                $total += $rows.Count
                $delc = @($rows | Where-Object { $_.Deletable -eq 'yes' }).Count
                Log "  $($dev.Hostname) - running $curVer; $($rows.Count) local image(s), $delc deletable"
            } catch { Log "  $($dev.Hostname) - $($_.Exception.Message)" }
        }
        UI {
            $txtStatus.Text = "Done - $($coll.Count) shown of $total local image(s) across $($devs.Count) device(s)"
            $fetchLock.Busy = $false; $fetchLock.Name = ''
        }
        Log "SW Cleanup fetch complete: $total local image(s) on $($devs.Count) device(s)."
    })
    [void]$ps.BeginInvoke()
}
function Invoke-SWDelete {
    $sel = @($dgSW.SelectedItems)
    if ($sel.Count -eq 0) { [System.Windows.MessageBox]::Show("Select one or more image rows in the grid first.","Delete Images","OK","Information")|Out-Null; return }
    # The running image is NEVER deleted, regardless of selection.
    $running = @($sel | Where-Object { $_.Running -eq 'yes' })
    $todo    = @($sel | Where-Object { $_.Running -ne 'yes' -and $_.Downloaded -eq 'yes' })
    if ($todo.Count -eq 0) { [System.Windows.MessageBox]::Show("Nothing deletable in the selection (running / not-downloaded images are skipped).","Delete Images","OK","Information")|Out-Null; return }
    $list = ($todo | ForEach-Object { "  $($_.Hostname)   $($_.Version)" + $(if ($_.Base -eq 'yes') { '   [BASE RELEASE]' } elseif ($_.Older -ne 'yes') { '   [NOT OLDER]' } else { '' }) }) -join "`n"
    $warn = if ($running.Count) { "`n`n$($running.Count) running image(s) in your selection will be skipped." } else { '' }
    $msg  = "Delete these $($todo.Count) software image(s)?$warn`n`n$list`n`nRuns 'request system software delete version <ver>' on each firewall. This removes the downloaded image file only; it does not affect the running system. Continue?"
    if ([System.Windows.MessageBox]::Show($msg,"Confirm Delete Software Images","YesNo","Warning") -ne 'Yes') { return }
    if (-not (Begin-Fetch 'SW Delete')) { return }
    $txtSWStatus.Text = "Deleting..."
    Write-Log "Deleting $($todo.Count) software image(s)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('todo',$todo)
    $rs.SessionStateProxy.SetVariable('allList',$script:ColSWAll)
    $rs.SessionStateProxy.SetVariable('coll',$script:ColSW)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtSWStatus)
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        $ok = 0; $fail = 0; $done = New-Object 'System.Collections.Generic.List[object]'
        foreach ($row in $todo) {
            try {
                $resp = Invoke-PANOperation -SkipCertificateCheck `
                            -Command "<request><system><software><delete><version>$($row.Version)</version></delete></software></system></request>" `
                            -Target $row.Serial
                if ([string]$resp.status -eq 'success') {
                    $ok++; $done.Add($row); Log "  $($row.Hostname) $($row.Version) - deleted"
                } else {
                    $fail++
                    $em = ''
                    try { $em = (@($resp.msg.line) | ForEach-Object { if ($_ -is [System.Xml.XmlElement]) { [string]$_.InnerText } else { [string]$_ } }) -join ' | ' } catch {}
                    if (-not $em) { try { $em = ([string]$resp.msg).Trim() } catch {} }
                    Log "  $($row.Hostname) $($row.Version) - delete status=$($resp.status) $em"
                }
            } catch { $fail++; Log "  $($row.Hostname) $($row.Version) - $($_.Exception.Message)" }
        }
        UI {
            foreach ($d in $done) { [void]$allList.Remove($d); [void]$coll.Remove($d) }
            $txtStatus.Text = "Deleted $ok image(s), $fail failed. ($($coll.Count) shown)"
            $fetchLock.Busy = $false; $fetchLock.Name = ''
        }
        Log "SW delete complete: $ok deleted, $fail failed."
    })
    [void]$ps.BeginInvoke()
}
$btnFetchSW.Add_Click({    Invoke-SWFetch @($script:DisplayColl | Where-Object Selected) })
$btnFetchSWAll.Add_Click({ Invoke-SWFetch @($script:DisplayColl) })
$btnDeleteSW.Add_Click({   Invoke-SWDelete })
$btnExportSW.Add_Click({   Export-CollToCSV $script:ColSWAll 'software-versions' })
$cbSWDeletableOnly.Add_Click({ Update-SWFilter })

# ── System resources ─────────────────────────────────────────
# Parses CDATA top output from <show><system><resources/></system></show>.
# PAN-OS 10.x outputs %Cpu(s) + KiB Mem; 11.x outputs %CpuN per-core + MiB Mem.
# Handle both. CDATA must come from .InnerText/.'#cdata-section', not [string]
# cast — XmlElement.ToString() returns the type name, not the text.
function Invoke-SystemFetch([object[]]$devs) {
    if (-not $devs -or $devs.Count -eq 0) { Write-Log "No devices selected for system fetch."; return }
    if (-not (Begin-Fetch 'System')) { return }
    $txtSystemStatus.Text = "Fetching..."
    Write-Log "Fetching system resources for $($devs.Count) device(s)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('devs',$devs)
    $rs.SessionStateProxy.SetVariable('coll',$script:ColSystem)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('writeTraceFn',${function:Write-Trace})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtSystemStatus)
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m)   { & $writeLogFn $m }
        function Trace($m) { & $writeTraceFn $m 'System' }
        function UI($b)    { $Window.Dispatcher.Invoke($b, 'Normal') }
        # Pull CDATA text out of a result node regardless of how pan-power exposed it.
        function GetCdata($node) {
            if (-not $node) { return '' }
            try { $t = [string]$node.'#cdata-section'; if ($t) { return $t } } catch {}
            try { $t = $node.InnerText;                if ($t) { return $t } } catch {}
            try { $t = [string]$node;                  if ($t) { return $t } } catch {}
            return ''
        }
        UI { $coll.Clear() }
        Trace "Started for $($devs.Count) devices"
        $ok = 0; $dumpedSample = $false
        foreach ($dev in $devs) {
            try {
                $row = [PSCustomObject]@{
                    Hostname = $dev.Hostname
                    Uptime   = '?'
                    CPU      = '?'
                    Mem      = '?'
                    Disk     = '?'
                    Sessions = '?'
                    Notes    = ''
                }
                # Uptime
                try {
                    $info = Invoke-PANOperation -SkipCertificateCheck `
                                -Command "<show><system><info/></system></show>" -Target $dev.Serial
                    $row.Uptime = [string]$info.result.system.uptime
                } catch {
                    $em = $_.Exception.Message
                    $row.Notes += "info err: $em; "
                    Trace "[$($dev.Hostname)] info exception: $em"
                }
                # CPU + Mem from `show system resources` (CDATA top output)
                try {
                    $res = Invoke-PANOperation -SkipCertificateCheck `
                                -Command "<show><system><resources/></system></show>" -Target $dev.Serial
                    $cdata = GetCdata $res.result
                    # First successful device: dump first 600 chars of CDATA so we can
                    # see what format PAN-OS is actually returning and tune the regex.
                    if ($cdata -and -not $dumpedSample) {
                        $dumpedSample = $true
                        $head = $cdata.Substring(0, [Math]::Min(600, $cdata.Length))
                        Trace "[$($dev.Hostname)] SAMPLE resources cdata(0..600):"
                        Trace $head
                    }
                    if ($cdata) {
                        # Try aggregate first (10.x), then first per-core line (11.x).
                        $mCpu = [regex]::Match($cdata, '%Cpu\(s\):\s*([\d.]+)\s*us,\s*([\d.]+)\s*sy')
                        if (-not $mCpu.Success) {
                            $mCpu = [regex]::Match($cdata, '%Cpu\d+\s*:\s*([\d.]+)\s*us,\s*([\d.]+)\s*sy')
                        }
                        if ($mCpu.Success) {
                            $us = [double]$mCpu.Groups[1].Value
                            $sy = [double]$mCpu.Groups[2].Value
                            $row.CPU = ('{0:N1}' -f ($us + $sy))
                        } else { $row.Notes += "cpu regex miss; " }
                        # Memory: KiB/MiB/GiB Mem (any unit — we just need the ratio).
                        $mMem = [regex]::Match($cdata, '(?:Ki|Mi|Gi)B\s+Mem\s*:?\s*([\d.]+)\s*total,\s*([\d.]+)\s*free')
                        if ($mMem.Success) {
                            $tot = [double]$mMem.Groups[1].Value
                            $fre = [double]$mMem.Groups[2].Value
                            if ($tot -gt 0) { $row.Mem = ('{0:N1}' -f ((1 - $fre/$tot) * 100)) }
                        } else { $row.Notes += "mem regex miss; " }
                    } else { $row.Notes += "resources empty; " }
                } catch {
                    $em = $_.Exception.Message
                    $row.Notes += "resources err: $em; "
                    Trace "[$($dev.Hostname)] resources exception: $em"
                }
                # Disk usage of root (or /panrepo if root isn't reported).
                try {
                    $disk = Invoke-PANOperation -SkipCertificateCheck `
                                -Command "<show><system><disk-space/></system></show>" -Target $dev.Serial
                    $cdata = GetCdata $disk.result
                    if ($cdata) {
                        $mDisk = [regex]::Match($cdata, '(?m)^\S+\s+\S+\s+\S+\s+\S+\s+(\d+)%\s+/\s*$')
                        if (-not $mDisk.Success) {
                            $mDisk = [regex]::Match($cdata, '(?m)^\S+\s+\S+\s+\S+\s+\S+\s+(\d+)%\s+/panrepo\b')
                        }
                        if ($mDisk.Success) { $row.Disk = $mDisk.Groups[1].Value }
                        else { $row.Notes += "disk regex miss; " }
                    } else { $row.Notes += "disk empty; " }
                } catch {
                    $em = $_.Exception.Message
                    $row.Notes += "disk err: $em; "
                    Trace "[$($dev.Hostname)] disk exception: $em"
                }
                # Session count
                try {
                    $ses = Invoke-PANOperation -SkipCertificateCheck `
                                -Command "<show><session><info/></session></show>" -Target $dev.Serial
                    $row.Sessions = [string]$ses.result.'num-active'
                } catch {}
                UI { $coll.Add($row) }
                $ok++
                Log "  $($dev.Hostname) - cpu:$($row.CPU)% mem:$($row.Mem)% disk:$($row.Disk)%"
            } catch {
                Log "  $($dev.Hostname) - $($_.Exception.Message)"
                Trace "[$($dev.Hostname)] outer exception: $($_.Exception)"
            }
        }
        UI {
            $txtStatus.Text = "Done - $ok / $($devs.Count) device(s)"
            $fetchLock.Busy = $false; $fetchLock.Name = ''
        }
        Log "System resources fetch complete."
    })
    [void]$ps.BeginInvoke()
}
$btnFetchSystem.Add_Click({    Invoke-SystemFetch @($script:DisplayColl | Where-Object Selected) })
$btnFetchSystemAll.Add_Click({ Invoke-SystemFetch @($script:DisplayColl) })
$btnExportSystem.Add_Click({   Export-CollToCSV $script:ColSystem 'system_resources' })

# ── Commit history ───────────────────────────────────────────
# Uses <show><jobs><all/></jobs></show> filtered to commit-type jobs. Returns
# a flat per-job row with admin, queued/end times, status. Sortable in the grid.
function Invoke-CommitsFetch([object[]]$devs) {
    if (-not $devs -or $devs.Count -eq 0) { Write-Log "No devices selected for commit history."; return }
    if (-not (Begin-Fetch 'Commits')) { return }
    $txtCommitsStatus.Text = "Fetching..."
    Write-Log "Fetching commit history from $($devs.Count) device(s)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('devs',$devs)
    $rs.SessionStateProxy.SetVariable('coll',$script:ColCommits)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtCommitsStatus)
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
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
                            -Command "<show><jobs><all></all></jobs></show>" -Target $dev.Serial
                $entries = @($resp.result.job)
                $commits = @($entries | Where-Object { $_.type -match '(?i)commit' } |
                             Sort-Object { $_.tenq } -Descending |
                             Select-Object -First 25)
                $rows = New-Object 'System.Collections.Generic.List[object]'
                foreach ($e in $commits) {
                    $rows.Add([PSCustomObject]@{
                        Hostname    = $dev.Hostname
                        JobID       = [string]$e.id
                        JobType     = [string]$e.type
                        Status      = [string]$e.status
                        Result      = [string]$e.result
                        Admin       = [string]$e.user
                        TimeQueued  = [string]$e.tenq
                        TimeEnded   = [string]$e.tfin
                        Description = [string]$e.description
                    })
                }
                UI { foreach ($r in $rows) { $coll.Add($r) } }
                $total += $rows.Count
                Log "  $($dev.Hostname) - $($rows.Count) commit job(s)"
            } catch { Log "  $($dev.Hostname) - $($_.Exception.Message)" }
        }
        UI {
            $txtStatus.Text = "Done - $total commit job(s) from $($devs.Count) device(s)"
            $fetchLock.Busy = $false; $fetchLock.Name = ''
        }
        Log "Commit history fetch complete: $total job(s)."
    })
    [void]$ps.BeginInvoke()
}
$btnFetchCommits.Add_Click({    Invoke-CommitsFetch @($script:DisplayColl | Where-Object Selected) })
$btnFetchCommitsAll.Add_Click({ Invoke-CommitsFetch @($script:DisplayColl) })
$btnExportCommits.Add_Click({   Export-CollToCSV $script:ColCommits 'commits' })

# ── GlobalProtect users ──────────────────────────────────────
function Update-GPFilter {
    $f = $txtGPFilter.Text.Trim()
    $hideRemote   = [bool]$cbGPHideRemote.IsChecked     # exclude entries with a real virtual IP (remote users)
    $hideInternal = [bool]$cbGPHideInternal.IsChecked   # exclude entries with virtual IP 0.0.0.0 (internal gateway)
    $dedup        = [bool]$cbGPDedup.IsChecked          # collapse same username across HA peers
    $script:ColGP.Clear()
    $seen = @{}
    foreach ($r in $script:ColGPAll) {
        $vip = ([string]$r.VirtualIP).Trim()
        $isZero     = ($vip -eq '0.0.0.0')
        $hasRealVip = ($vip -ne '' -and $vip -ne '0.0.0.0')
        if ($hideRemote   -and $hasRealVip) { continue }
        if ($hideInternal -and $isZero)     { continue }
        if ($f -ne '') {
            $match = $false
            try { if (($r.Username -match $f) -or ($r.Computer -match $f) -or ($r.ClientIP -match $f) -or ($r.VirtualIP -match $f) -or ($r.PublicIP -match $f)) { $match = $true } } catch { $match = $true }
            if (-not $match) { continue }
        }
        if ($dedup) {
            $key = ([string]$r.Username).ToLower()
            if ($key -ne '' -and $seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
        }
        $script:ColGP.Add($r)
    }
    $txtGPStatus.Text = "Showing $($script:ColGP.Count) of $($script:ColGPAll.Count) sessions"
}
function Invoke-GPFetch([object[]]$devs) {
    if (-not $devs -or $devs.Count -eq 0) { Write-Log "No DC gateways to query for GP users."; return }
    if (-not (Begin-Fetch 'GP Users')) { return }
    $txtGPStatus.Text = "Fetching..."
    Write-Log "Fetching GlobalProtect users from $($devs.Count) DC gateway(s)..."
    $script:ColGPAll.Clear(); $script:ColGP.Clear()
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('devs',$devs)
    $rs.SessionStateProxy.SetVariable('allList',$script:ColGPAll)
    $rs.SessionStateProxy.SetVariable('coll',$script:ColGP)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtGPStatus)
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        $total = 0; $withUsers = 0
        foreach ($dev in $devs) {
            try {
                $resp = Invoke-PANOperation -SkipCertificateCheck `
                            -Command "<show><global-protect-gateway><current-user/></global-protect-gateway></show>" `
                            -Target $dev.Serial
                if ($resp.status -ne 'success') { continue }
                # Skip placeholder rows: entries with empty username are not real
                # sessions (some PAN-OS versions emit an empty <entry/> when zero users).
                $entries = @($resp.result.entry | Where-Object {
                    $_ -is [System.Xml.XmlElement] -and ([string]$_.username).Trim() -ne ''
                })
                if ($entries.Count -eq 0) { continue }
                $rows = New-Object 'System.Collections.Generic.List[object]'
                foreach ($e in $entries) {
                    $rows.Add([PSCustomObject]@{
                        Hostname  = $dev.Hostname
                        Username  = [string]$e.username
                        Computer  = [string]$e.'computer'
                        ClientIP  = [string]$e.'client-ip'
                        VirtualIP = [string]$e.'virtual-ip'
                        PublicIP  = [string]$e.'public-ip'
                        LoginTime = [string]$e.'login-time'
                        OS        = [string]$e.'client-os'
                    })
                }
                UI {
                    foreach ($r in $rows) { $allList.Add($r); $coll.Add($r) }
                    $txtStatus.Text = "Fetched $($total + $rows.Count) sessions..."
                }
                $total     += $rows.Count
                $withUsers += 1
                Log "  $($dev.Hostname) - $($rows.Count) GP session(s)"
            } catch { Log "  $($dev.Hostname) - $($_.Exception.Message)" }
        }
        UI {
            $txtStatus.Text = "Done - $total session(s) across $withUsers / $($devs.Count) gateway(s)"
            $fetchLock.Busy = $false; $fetchLock.Name = ''
        }
        Log "GP user fetch complete: $total session(s) on $withUsers gateway(s)."
    })
    [void]$ps.BeginInvoke()
}

# Helper: restrict any device list to the data-center firewalls. Branch FWs
# don't run a GP gateway so querying them is wasted round trips. Always applied.
function Get-DCDevices([object[]]$source) {
    @($source | Where-Object { $script:DataCenterFWs -contains $_.Hostname })
}

$btnFetchGP.Add_Click({
    $sel = Get-DCDevices @($script:DisplayColl | Where-Object Selected)
    if ($sel.Count -eq 0) {
        Write-Log "No DC gateways in selection. Use 'All' to query all loaded DC gateways."
        return
    }
    Invoke-GPFetch $sel
})
$btnFetchGPAll.Add_Click({
    $dc = Get-DCDevices @($script:DisplayColl)
    if ($dc.Count -eq 0) {
        Write-Log "None of the DC gateways are loaded — did 'Load Devices' finish?"
        return
    }
    Invoke-GPFetch $dc
})
$btnExportGP.Add_Click({        Export-CollToCSV $script:ColGPAll 'gp_users' })
$txtGPFilter.Add_TextChanged({  Update-GPFilter })
$btnGPClearFilter.Add_Click({   $txtGPFilter.Text = '' })
$cbGPHideRemote.Add_Click({   Update-GPFilter })
$cbGPHideInternal.Add_Click({ Update-GPFilter })
$cbGPDedup.Add_Click({        Update-GPFilter })

# ── Sessions ────────────────────────────────────────────────
# Active-session query + selective clear. PAN-OS sessions tables can be huge
# (millions on a busy DC firewall), so the fetch is always bounded by a
# per-firewall cap (default 500). The filter textbox accepts space-separated
# key=value pairs and gets translated into a PAN-OS <filter> element.
#
# Show command shape:
#   <show><session><all>
#     <filter>
#       <source>1.1.1.1</source>
#       <destination>2.2.2.2</destination>
#       <application>ssh</application>
#       <source-user>DOMAIN\user</source-user>
#       <protocol>6</protocol>          ← number, or 'tcp'/'udp'/'icmp'
#       <source-port>1234</source-port>
#       <destination-port>22</destination-port>
#       <state>active</state>
#     </filter>
#     <count>500</count>                ← cap
#   </all></session></show>
#
# Clear command shape (per-session):
#   <clear><session><id>NNNN</id></session></clear>

# Parse the user's filter textbox into the inner XML for <filter>...</filter>.
# Returns an empty string if no recognized keys; that's fine, PAN-OS accepts
# <filter></filter> as "no filter".
function Build-SessionFilter([string]$text) {
    if ([string]::IsNullOrWhiteSpace($text)) { return '' }
    $map = @{
        src     = 'source'
        source  = 'source'
        dst     = 'destination'
        dest    = 'destination'
        destination = 'destination'
        app     = 'application'
        application = 'application'
        user    = 'source-user'
        proto   = 'protocol'
        protocol = 'protocol'
        sport   = 'source-port'
        dport   = 'destination-port'
        state   = 'state'
    }
    $protoNames = @{ tcp = '6'; udp = '17'; icmp = '1' }
    $xml = ''
    foreach ($tok in ($text -split '\s+')) {
        if ($tok -eq '') { continue }
        $eq = $tok.IndexOf('=')
        if ($eq -lt 1) { continue }
        $k = $tok.Substring(0, $eq).Trim().ToLower()
        $v = $tok.Substring($eq + 1).Trim()
        if (-not $map.ContainsKey($k) -or $v -eq '') { continue }
        $tag = $map[$k]
        if ($tag -eq 'protocol' -and $protoNames.ContainsKey($v.ToLower())) { $v = $protoNames[$v.ToLower()] }
        # XML-escape value
        $v = $v.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;')
        $xml += "<$tag>$v</$tag>"
    }
    return $xml
}

function Invoke-SessionsFetch([object[]]$devs) {
    if (-not $devs -or $devs.Count -eq 0) { Write-Log "No devices selected for Sessions fetch."; return }
    $filterText = $txtSessionFilter.Text
    $capText    = $txtSessionCap.Text.Trim()
    $cap        = 500
    if ($capText -match '^\d+$') { $cap = [int]$capText }
    if ($cap -lt 1)    { $cap = 1 }
    if ($cap -gt 5000) { $cap = 5000 }
    $filterXml  = Build-SessionFilter $filterText
    if (-not (Begin-Fetch 'Sessions')) { return }
    $txtSessionsStatus.Text = "Fetching..."
    Write-Log "Fetching sessions on $($devs.Count) device(s); cap=$cap filter='$filterText'..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('devs',$devs)
    $rs.SessionStateProxy.SetVariable('coll',$script:ColSessions)
    $rs.SessionStateProxy.SetVariable('filterXml',$filterXml)
    $rs.SessionStateProxy.SetVariable('cap',$cap)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('writeTraceFn',${function:Write-Trace})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtSessionsStatus)
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m)   { & $writeLogFn $m }
        function Trace($m) { & $writeTraceFn $m }
        function UI($b)    { $Window.Dispatcher.Invoke($b, 'Normal') }
        function GetProp($obj, [string[]]$names) {
            foreach ($n in $names) {
                try {
                    $v = $obj.$n
                    if ($null -ne $v -and ([string]$v).Trim() -ne '') { return [string]$v }
                } catch {}
            }
            return ''
        }
        UI { $coll.Clear() }
        # "show session all [filter ...]" — there is no valid server-side count element
        # inside <all> (it makes PAN-OS return status=error), so the cap is applied
        # client-side below. Omit <filter> entirely when no filter is set.
        $filterPart = if ($filterXml) { "<filter>$filterXml</filter>" } else { '' }
        $cmd = "<show><session><all>$filterPart</all></session></show>"
        $total = 0; $withSess = 0; $firstErr = $true
        foreach ($dev in $devs) {
            try {
                $resp = Invoke-PANOperation -SkipCertificateCheck -Command $cmd -Target $dev.Serial
                $st = [string]$resp.status
                if ($st -ne 'success') {
                    $errMsg = ''
                    try {
                        $ln = $resp.msg.line
                        if ($ln) { $errMsg = (@($ln) | ForEach-Object { if ($_ -is [System.Xml.XmlElement]) { [string]$_.InnerText } else { [string]$_ } } | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ' | ' }
                    } catch {}
                    if (-not $errMsg) { try { $errMsg = ([string]$resp.msg.InnerText).Trim() } catch {} }
                    if (-not $errMsg) { try { $errMsg = ([string]$resp.msg).Trim() } catch {} }
                    if ($firstErr) { try { Trace "[$($dev.Hostname)] session error raw: $([string]$resp.OuterXml)" } catch {}; $firstErr = $false }
                    Log "  $($dev.Hostname) - status=$st $errMsg"
                    continue
                }
                # Sessions land at .result.member (XmlElement[])
                $members = @()
                try { $members = @($resp.result.member | Where-Object { $_ -is [System.Xml.XmlElement] }) } catch {}
                if ($members.Count -gt $cap) { $members = @($members[0..($cap-1)]) }
                if ($members.Count -eq 0) {
                    # First device: dump a sample response shape to trace so we can debug
                    if ($total -eq 0 -and $withSess -eq 0) {
                        try { Trace "[$($dev.Hostname)] empty session result; sample OuterXml: $([string]($resp.OuterXml).Substring(0,[Math]::Min(800,[string]($resp.OuterXml).Length)))" } catch {}
                    }
                    Log "  $($dev.Hostname) - 0 sessions matched"
                    continue
                }
                $rows = New-Object 'System.Collections.Generic.List[object]'
                foreach ($m in $members) {
                    $rows.Add([PSCustomObject]@{
                        Hostname    = $dev.Hostname
                        Serial      = $dev.Serial   # not bound to a column; used by Clear
                        SessionID   = GetProp $m @('id','session-id')
                        FromZone    = GetProp $m @('from','zone')
                        ToZone      = GetProp $m @('to')
                        Source      = GetProp $m @('source','src')
                        SPort       = GetProp $m @('sport','source-port')
                        Destination = GetProp $m @('destination','dst','dest')
                        DPort       = GetProp $m @('dport','destination-port','dst-port')
                        Protocol    = GetProp $m @('protocol','proto')
                        Application = GetProp $m @('application','app')
                        SrcUser     = GetProp $m @('source-user','src-user','user')
                        State       = GetProp $m @('state')
                        Type        = GetProp $m @('type','flags')
                    })
                }
                UI { foreach ($r in $rows) { $coll.Add($r) } }
                $total    += $rows.Count
                $withSess += 1
                Log "  $($dev.Hostname) - $($rows.Count) session(s)"
            } catch { Log "  $($dev.Hostname) - $($_.Exception.Message)" }
        }
        UI {
            $txtStatus.Text = "Done - $total session(s) across $withSess / $($devs.Count) device(s) (cap=$cap)"
            $fetchLock.Busy = $false; $fetchLock.Name = ''
        }
        Log "Sessions fetch complete: $total session(s) on $withSess device(s)."
    })
    [void]$ps.BeginInvoke()
}

# Clear the sessions currently selected in dgSessions. Each row carries its
# firewall Serial so we can target the right device.
function Invoke-SessionsClear {
    $sel = @($dgSessions.SelectedItems)
    if ($sel.Count -eq 0) {
        [System.Windows.MessageBox]::Show("Select one or more session rows in the grid first.", "No selection", "OK", "Information") | Out-Null
        return
    }
    # Build a preview list - hostname:id (source -> dest:dport / app)
    $preview = ($sel | Select-Object -First 12 | ForEach-Object {
        "$($_.Hostname):$($_.SessionID)  $($_.Source) -> $($_.Destination):$($_.DPort) ($($_.Application))"
    }) -join "`n  "
    if ($sel.Count -gt 12) { $preview += "`n  ... and $($sel.Count - 12) more" }
    $msg = "Clear $($sel.Count) session(s)?`n`n  $preview`n`nThe firewall will tear down the flow(s); clients will reconnect as needed."
    if ([System.Windows.MessageBox]::Show($msg, "Confirm Clear Sessions", "YesNo", "Warning") -ne 'Yes') { return }
    if (-not (Begin-Fetch 'Sessions Clear')) { return }
    $txtSessionsStatus.Text = "Clearing..."
    Write-Log "Clearing $($sel.Count) session(s)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('rows',$sel)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtSessionsStatus)
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        $ok = 0
        foreach ($r in $rows) {
            $serial = [string]$r.Serial
            $id     = [string]$r.SessionID
            if (-not $serial -or -not $id) { Log "  skipping row with missing serial/id"; continue }
            try {
                $resp = Invoke-PANOperation -SkipCertificateCheck `
                            -Command ("<clear><session><id>" + $id + "</id></session></clear>") `
                            -Target $serial
                $st = [string]$resp.status
                if ($st -eq 'success') { $ok++; Log "  $($r.Hostname) - cleared session $id" }
                else { Log "  $($r.Hostname) - session $id status=$st" }
            } catch { Log "  $($r.Hostname) - session $id error: $($_.Exception.Message)" }
        }
        UI {
            $txtStatus.Text = "Cleared $ok / $($rows.Count) session(s)"
            $fetchLock.Busy = $false; $fetchLock.Name = ''
        }
        Log "Sessions clear complete: $ok / $($rows.Count)."
    })
    [void]$ps.BeginInvoke()
}

$btnFetchSessions.Add_Click({    Invoke-SessionsFetch @($script:DisplayColl | Where-Object Selected) })
$btnFetchSessionsAll.Add_Click({ Invoke-SessionsFetch @($script:DisplayColl) })
$btnExportSessions.Add_Click({   Export-CollToCSV $script:ColSessions 'sessions' })
$btnClearSessions.Add_Click({    Invoke-SessionsClear })

# ── Certs ────────────────────────────────────────────────────
# Parses CDATA from <show><sslmgr-store><config-certificate-info/></sslmgr-store></show>
# which dumps text lines per cert like:
#   cert-name:       my-cert
#   db-name:         /CN=cn/...
#   issuer:          /CN=issuer/...
#   db-type:         RSA
#   db-exp-date:     YYYY-MM-DD HH:MM:SS
#   not-valid-before: ...
#   not-valid-after: ...
#   common-name:     ...
#   has-private-key: yes|no
# Fields are stable across 9.x-11.x. Each cert block ends with a blank line
# (or the next "cert-name:" header).
function Update-CertFilter {
    $f    = $txtCertFilter.Text.Trim()
    $days = $null
    $dt   = $txtCertDays.Text.Trim()
    if ($dt -match '^\d+$') { $days = [int]$dt }
    $script:ColCerts.Clear()
    foreach ($r in $script:ColCertsAll) {
        if ($f -ne '') {
            $hay = "$($r.CertName) $($r.CN) $($r.Issuer)"
            try { if ($hay -notmatch $f) { continue } } catch { continue }
        }
        if ($null -ne $days) {
            $dl = $r.DaysLeft
            if ($dl -is [int]) {
                if ($dl -gt $days) { continue }
            } else {
                continue   # non-numeric DaysLeft (parse failure) — hide when threshold set
            }
        }
        $script:ColCerts.Add($r)
    }
    $txtCertsStatus.Text = "Shown: $($script:ColCerts.Count) / $($script:ColCertsAll.Count) cert(s)"
}

function Invoke-CertsFetch([object[]]$devs) {
    if (-not $devs -or $devs.Count -eq 0) { Write-Log "No devices selected for Certs."; return }
    if (-not (Begin-Fetch 'Certs')) { return }
    $txtCertsStatus.Text = "Fetching..."
    Write-Log "Fetching certificates from $($devs.Count) device(s)..."
    $script:ColCertsAll.Clear(); $script:ColCerts.Clear()
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('devs',$devs)
    $rs.SessionStateProxy.SetVariable('allList',$script:ColCertsAll)
    $rs.SessionStateProxy.SetVariable('coll',$script:ColCerts)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('writeTraceFn',${function:Write-Trace})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtCertsStatus)
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m)   { & $writeLogFn $m }
        function Trace($m) { & $writeTraceFn $m }
        function UI($b)    { $Window.Dispatcher.Invoke($b, 'Normal') }

        # Define helper as a scriptblock so closure over $blk works cleanly.
        $findLineSB = {
            param([string]$pattern, [string]$haystack)
            $m = [regex]::Match($haystack, $pattern, 'IgnoreCase,Multiline')
            if ($m.Success) { return $m.Groups[1].Value.Trim() } else { return '' }
        }

        function ParseCertText([string]$text, [string]$hostname, $findLine) {
            $rows = New-Object 'System.Collections.Generic.List[object]'
            if ([string]::IsNullOrWhiteSpace($text)) { return $rows }
            # PAN-OS config-certificate-info output: each cert is a block that begins
            # with a column-0 header line (<fingerprint-hex>:<issuer-subjecthash>, or a
            # bare serial), followed by indented "key: value" lines. Fields seen:
            #   issuer:, db-exp-date:, db-serialno:, db-name:, db-status:  (no cert-name)
            # Split before every non-indented line; keep the header with its block.
            $blocks = [regex]::Split($text, "(?=^\S)", 'Multiline')
            foreach ($blk in $blocks) {
                if ([string]::IsNullOrWhiteSpace($blk)) { continue }
                $dbname = & $findLine '^\s*(?:db-name|subject)\s*:\s*(.+)$'  $blk
                $issuer = & $findLine '^\s*issuer\s*:\s*(.+)$'               $blk
                $expdt  = & $findLine '^\s*db-exp-date\s*:\s*(.+)$'          $blk
                $serial = & $findLine '^\s*db-serialno\s*:\s*(\S+)'          $blk
                $dbstat = & $findLine '^\s*db-status\s*:\s*(\S+)'            $blk
                # Skip non-cert blocks (e.g. a truncated trailing header with no fields)
                if (-not $dbname -and -not $issuer -and -not $expdt) { continue }
                # CN from the subject DN (e.g. /CN=Foo or /O=..,CN=..)
                $cn = $dbname
                if ($dbname) { $m = [regex]::Match($dbname, '(?i)CN\s*=\s*([^/,]+)'); if ($m.Success) { $cn = $m.Groups[1].Value.Trim() } }
                $issuerCN = $issuer
                if ($issuer) { $m = [regex]::Match($issuer, '(?i)CN\s*=\s*([^/,]+)'); if ($m.Success) { $issuerCN = $m.Groups[1].Value.Trim() } }
                # db-exp-date looks like: 280118134525Z(Jan 18 13:45:25 2028 GMT)
                # Prefer the human-readable date in parens (has a full 4-digit year);
                # fall back to the leading ASN.1 UTCTime (YYMMDDHHMMSSZ).
                $naft = ''; $exp = [DateTime]::MinValue; $parsed = $false
                if ($expdt) {
                    $mp = [regex]::Match($expdt, '\(([^)]+)\)')
                    $human = if ($mp.Success) { $mp.Groups[1].Value.Trim() } else { '' }
                    if ($human) {
                        $naft = $human
                        foreach ($fmt in @('MMM d HH:mm:ss yyyy GMT','MMM dd HH:mm:ss yyyy GMT')) {
                            if ([DateTime]::TryParseExact($human, $fmt, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$exp)) { $parsed = $true; break }
                        }
                    }
                    if (-not $parsed) {
                        $mu = [regex]::Match($expdt, '^\s*(\d{12})Z')
                        if ($mu.Success -and [DateTime]::TryParseExact($mu.Groups[1].Value, 'yyMMddHHmmss', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$exp)) {
                            $parsed = $true; if (-not $naft) { $naft = $exp.ToString('yyyy-MM-dd HH:mm:ss') }
                        }
                    }
                }
                $daysLeft = '?'; $status = ''
                if ($parsed) {
                    $daysLeft = [int]([Math]::Floor(($exp - (Get-Date)).TotalDays))
                    if     ($daysLeft -lt 0)  { $status = "EXPIRED $($daysLeft * -1)d ago" }
                    elseif ($daysLeft -le 90) { $status = "expires in $daysLeft d" }
                    else                      { $status = "OK" }
                } elseif ($dbstat -and $dbstat -ne 'V') {
                    $status = "db-status $dbstat"
                }
                $rows.Add([PSCustomObject]@{
                    Hostname      = $hostname
                    CertName      = $dbname
                    CN            = $cn
                    Issuer        = $issuerCN
                    NotBefore     = ''
                    NotAfter      = $naft
                    DaysLeft      = $daysLeft
                    HasPrivateKey = ''
                    Status        = $status
                })
            }
            return $rows
        }

        $total = 0; $withCerts = 0; $first = $true
        foreach ($dev in $devs) {
            try {
                $resp = Invoke-PANOperation -SkipCertificateCheck `
                            -Command "<show><sslmgr-store><config-certificate-info/></sslmgr-store></show>" `
                            -Target $dev.Serial
                if ($resp.status -ne 'success') { Log "  $($dev.Hostname) - status=$($resp.status)"; continue }
                # Text typically lives in .result CDATA
                $cdata = ''
                try { $cdata = [string]$resp.result.'#cdata-section' } catch {}
                if (-not $cdata) { try { $cdata = [string]$resp.result.InnerText } catch {} }
                if (-not $cdata) { try { $cdata = [string]$resp.InnerText } catch {} }
                if ($first -and -not $cdata) { try { Log "[Certs DIAG] $($dev.Hostname) empty cdata; raw: $([string]($resp.OuterXml).Substring(0,[Math]::Min(1500,[string]($resp.OuterXml).Length)))" } catch {}; $first = $false }
                if ($first -and $cdata) {
                    $sample = if ($cdata.Length -gt 1000) { $cdata.Substring(0, 1000) } else { $cdata }
                    Trace "[$($dev.Hostname)] cert-info sample: $sample"
                    $first = $false
                }
                $rows = ParseCertText $cdata $dev.Hostname $findLineSB
                if ($rows.Count -eq 0) {
                    Log "  $($dev.Hostname) - 0 certs parsed"
                    continue
                }
                UI {
                    foreach ($r in $rows) { $allList.Add($r); $coll.Add($r) }
                }
                $total += $rows.Count
                $withCerts += 1
                Log "  $($dev.Hostname) - $($rows.Count) cert(s)"
            } catch { Log "  $($dev.Hostname) - $($_.Exception.Message)" }
        }
        UI {
            $txtStatus.Text = "Done - $total cert(s) across $withCerts / $($devs.Count) device(s)"
            $fetchLock.Busy = $false; $fetchLock.Name = ''
        }
        Log "Certs fetch complete: $total cert(s) on $withCerts device(s)."
    })
    [void]$ps.BeginInvoke()
}
$btnFetchCerts.Add_Click({       Invoke-CertsFetch @($script:DisplayColl | Where-Object Selected) })
$btnFetchCertsAll.Add_Click({    Invoke-CertsFetch @($script:DisplayColl) })
$btnExportCerts.Add_Click({      Export-CollToCSV $script:ColCertsAll 'certificates' })
$txtCertFilter.Add_TextChanged({ Update-CertFilter })
$txtCertDays.Add_TextChanged({   Update-CertFilter })
$btnCertClearFilter.Add_Click({  $txtCertFilter.Text = ''; $txtCertDays.Text = '' })

# ── Ping / Traceroute from firewall ──────────────────────────
# IMPORTANT: PAN-OS XML API blocks <ping> and <traceroute> on most builds —
# they return error code 17 "not available to xmlapi client". This tab will
# attempt the command anyway; if the API rejects it, the error appears in
# the output box with a friendly explanation. Workaround: use the firewall's
# Web UI → Network → Troubleshooting → Ping, or SSH directly.
function Append-PingOutput([string]$text) {
    UI {
        $txtPingOutput.AppendText($text + "`r`n")
        $txtPingOutput.ScrollToEnd()
    }
}

function Invoke-PingLoadInterfaces {
    $dev = $cbPingFW.SelectedItem
    if (-not $dev) {
        [System.Windows.MessageBox]::Show("Pick a firewall first.", "No firewall", "OK", "Information") | Out-Null
        return
    }
    if (-not (Begin-Fetch 'Ping Ifaces')) { return }
    $txtPingStatus.Text = "Loading interfaces from $($dev.Hostname)..."
    Append-PingOutput "──── Loading interfaces from $($dev.Hostname) ────"
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('dev',$dev)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('cbSrc',$cbPingSrc)
    $rs.SessionStateProxy.SetVariable('txtOut',$txtPingOutput)
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtPingStatus)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        try {
            $resp = Invoke-PANOperation -SkipCertificateCheck `
                        -Command "<show><interface>all</interface></show>" `
                        -Target $dev.Serial
            $items = New-Object 'System.Collections.Generic.List[string]'
            # Logical L3 ifnet/entry with name + ip; v9-v11 path:
            #   result.ifnet.entry[].name + .ip
            try {
                foreach ($e in @($resp.result.ifnet.entry | Where-Object { $_ -is [System.Xml.XmlElement] })) {
                    $name = [string]$e.name
                    $ip   = [string]$e.ip
                    if ($ip -and $ip -ne 'N/A' -and $ip -ne '0.0.0.0') {
                        $items.Add("$name ($ip)")
                    }
                }
            } catch {}
            # Hardware fallback (some pulls land under result.hw.entry)
            if ($items.Count -eq 0) {
                try {
                    foreach ($e in @($resp.result.hw.entry | Where-Object { $_ -is [System.Xml.XmlElement] })) {
                        $name = [string]$e.name
                        $ip   = [string]$e.ip
                        if ($ip -and $ip -ne 'N/A' -and $ip -ne '0.0.0.0') {
                            $items.Add("$name ($ip)")
                        }
                    }
                } catch {}
            }
            UI {
                $cbSrc.Items.Clear()
                foreach ($s in ($items | Sort-Object -Unique)) { [void]$cbSrc.Items.Add($s) }
                if ($cbSrc.Items.Count -gt 0) { $cbSrc.SelectedIndex = 0 }
                $txtOut.AppendText("Loaded $($cbSrc.Items.Count) interface(s) with IPs from $($dev.Hostname)`r`n")
                $txtStatus.Text = "Loaded $($cbSrc.Items.Count) interface(s) from $($dev.Hostname)"
                $fetchLock.Busy = $false; $fetchLock.Name = ''
            }
            Log "Loaded $($items.Count) interface(s) from $($dev.Hostname)"
        } catch {
            UI {
                $txtOut.AppendText("ERROR: $($_.Exception.Message)`r`n")
                $txtStatus.Text = "Interface load failed"
                $fetchLock.Busy = $false; $fetchLock.Name = ''
            }
            Log "Interface load failed on $($dev.Hostname): $($_.Exception.Message)"
        }
    })
    [void]$ps.BeginInvoke()
}

function Invoke-PingFromFW([string]$cmdKind) {
    $dev = $cbPingFW.SelectedItem
    if (-not $dev) { [System.Windows.MessageBox]::Show("Pick a firewall.", "Missing", "OK", "Information") | Out-Null; return }
    $target = $txtPingTarget.Text.Trim()
    if (-not $target) { [System.Windows.MessageBox]::Show("Enter a target host/IP.", "Missing", "OK", "Information") | Out-Null; return }
    $srcText = ''
    try { $srcText = [string]$cbPingSrc.Text } catch {}
    if (-not $srcText -and $cbPingSrc.SelectedItem) { $srcText = [string]$cbPingSrc.SelectedItem }
    # Extract IP from "iface (ip)" — keep just the IP
    $src = $srcText
    $m = [regex]::Match($srcText, '\(([\d\.:]+)(?:/\d+)?\)\s*$')
    if ($m.Success) { $src = $m.Groups[1].Value }
    elseif ($srcText -match '^[\d\.:]+(?:/\d+)?$') { $src = ($srcText -split '/')[0] }
    $count = 5
    if ($txtPingCount.Text -match '^\d+$') { $count = [int]$txtPingCount.Text }
    if ($count -lt 1)  { $count = 1 }
    if ($count -gt 50) { $count = 50 }

    # The XML API blocks ping/traceroute (code 17, "not available to xmlapi client"),
    # so we SSH to the firewall's mgmt IP and run the real CLI command. Reuses the
    # Panorama credentials captured on Connect. Requires the Posh-SSH module.
    if ($cmdKind -eq 'ping') { $cliCmd = "ping count $count source $src host $target"; $label = 'PING' }
    else                     { $cliCmd = "traceroute source $src host $target";       $label = 'TRACEROUTE' }
    $fwIp = ''
    foreach ($pn in @('IPAddress','IP','MgmtIP','Address')) { try { $v=[string]$dev.$pn; if ($v) { $fwIp=$v; break } } catch {} }
    if (-not $fwIp)               { Append-PingOutput "No mgmt IP known for $($dev.Hostname) - cannot SSH."; return }
    if (-not $script:PanCred.User) { Append-PingOutput "Not connected - connect first (SSH reuses your Panorama login)."; return }
    if (-not (Begin-Fetch "Ping/$cmdKind")) { return }
    $txtPingStatus.Text = "SSH $label on $($dev.Hostname)..."
    Append-PingOutput ""
    Append-PingOutput "──── $label via SSH to $($dev.Hostname) ($fwIp) src=$src target=$target count=$count ────"
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('fwIp',$fwIp)
    $rs.SessionStateProxy.SetVariable('cliCmd',$cliCmd)
    $rs.SessionStateProxy.SetVariable('label',$label)
    $rs.SessionStateProxy.SetVariable('panUser',$script:PanCred.User)
    $rs.SessionStateProxy.SetVariable('panPass',$script:PanCred.Pass)
    $rs.SessionStateProxy.SetVariable('hostName',[string]$dev.Hostname)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('txtOut',$txtPingOutput)
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtPingStatus)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        function Out([string]$t) { UI { $txtOut.AppendText($t + "`r`n"); $txtOut.ScrollToEnd() } }
        try {
            if (-not (Get-Module -ListAvailable -Name 'Posh-SSH')) {
                Out "Posh-SSH module is not installed. Install it once (no admin needed):"
                Out "    Install-Module Posh-SSH -Scope CurrentUser"
                Out "Then re-run. (It provides the SSH client used to reach the firewall CLI.)"
                UI { $txtStatus.Text = "Posh-SSH not installed"; $fetchLock.Busy=$false; $fetchLock.Name='' }
                return
            }
            # Import Posh-SSH only to load its bundled Renci.SshNet assembly; we drive
            # SSH.NET directly so we can answer the firewall's pre-login legal banner.
            # Many PAN-OS boxes use keyboard-interactive auth with a prompt like
            #   "Do you accept and acknowledge the statement above ? (yes/no) :"
            # New-SSHSession leaves that prompt unanswered (Response is null) and fails,
            # so we wire a KeyboardInteractive handler that says "yes" to the banner and
            # supplies the password to any password prompt.
            Import-Module Posh-SSH -ErrorAction Stop
            $keyb = New-Object Renci.SshNet.KeyboardInteractiveAuthenticationMethod($panUser)
            $keyb.add_AuthenticationPrompt({ param($snd,$evt)
                foreach ($p in $evt.Prompts) {
                    $req = [string]$p.Request
                    if ($req -match '(?i)password') { $p.Response = $panPass }
                    elseif ($req -match '(?i)yes\s*/\s*no|accept|acknowledge|\(y/n\)') { $p.Response = 'yes' }
                    else { $p.Response = $panPass }
                }
            })
            $pwd  = New-Object Renci.SshNet.PasswordAuthenticationMethod($panUser, $panPass)
            $conn = New-Object Renci.SshNet.ConnectionInfo($fwIp, 22, $panUser, @($keyb, $pwd))
            $conn.Timeout = [TimeSpan]::FromSeconds(20)
            $client = New-Object Renci.SshNet.SshClient($conn)
            $client.Connect()
            try {
                $stream = $client.CreateShellStream('vt100', 200, 50, 800, 600, 8192)
                Start-Sleep -Milliseconds 1200; [void]$stream.Read()
                $stream.WriteLine('set cli pager off'); Start-Sleep -Milliseconds 700; [void]$stream.Read()
                $stream.WriteLine($cliCmd)
                $sb = New-Object System.Text.StringBuilder
                $deadline = (Get-Date).AddSeconds(120)
                while ((Get-Date) -lt $deadline) {
                    Start-Sleep -Milliseconds 700
                    $chunk = ''
                    try { $chunk = $stream.Read() } catch {}
                    if ($chunk) {
                        [void]$sb.Append($chunk)
                        UI { $txtOut.AppendText($chunk); $txtOut.ScrollToEnd() }
                    }
                    $acc = $sb.ToString()
                    # Stop once the CLI prompt (user@host> ) returns after the command output
                    if ($acc.Length -gt ($cliCmd.Length + 8) -and $acc -match "(?m)[>#]\s*$") { break }
                }
            } finally {
                try { $client.Disconnect() } catch {}
                try { $client.Dispose() } catch {}
            }
            UI { $txtOut.AppendText("`r`n"); $txtOut.ScrollToEnd(); $txtStatus.Text = "$label complete on $hostName"; $fetchLock.Busy=$false; $fetchLock.Name='' }
            Log "$label via SSH on $hostName complete."
        } catch {
            Out "SSH ERROR: $($_.Exception.Message)"
            Out "(Check: Posh-SSH installed, mgmt-IP reachable from this PC, and your login is valid on the firewall.)"
            UI { $txtStatus.Text = "$label failed (SSH)"; $fetchLock.Busy=$false; $fetchLock.Name='' }
            Log "$label via SSH on $hostName failed: $($_.Exception.Message)"
        }
    })
    [void]$ps.BeginInvoke()
}
$btnPingLoadIfaces.Add_Click({  Invoke-PingLoadInterfaces })
$btnRunPing.Add_Click({         Invoke-PingFromFW 'ping' })
$btnRunTrace.Add_Click({        Invoke-PingFromFW 'trace' })
$btnClearPingOutput.Add_Click({ $txtPingOutput.Clear() })

# ── BGP / OSPF peers ─────────────────────────────────────────
# Unified grid; toggles let user choose protocols. BGP returns <entry peer="..">
# (attribute, not child) — handle both. OSPF returns <entry> children with
# neighbor-router-id / area-id / status.
function Update-PeersFilter {
    $script:ColPeers.Clear()
    $onlyDown = $cbPeersOnlyDown.IsChecked
    foreach ($r in $script:ColPeersAll) {
        if ($onlyDown) {
            $s = [string]$r.State
            if ($s -match '(?i)Established|Full|2-?Way') { continue }
        }
        $script:ColPeers.Add($r)
    }
    $txtPeersStatus.Text = "Shown: $($script:ColPeers.Count) / $($script:ColPeersAll.Count) peer(s)"
}

function Invoke-PeersFetch([object[]]$devs) {
    if (-not $devs -or $devs.Count -eq 0) { Write-Log "No devices selected for Peers."; return }
    $doBGP  = [bool]$cbPeersBGP.IsChecked
    $doOSPF = [bool]$cbPeersOSPF.IsChecked
    if (-not $doBGP -and -not $doOSPF) { Write-Log "Tick BGP or OSPF (or both)."; return }
    if (-not (Begin-Fetch 'Peers')) { return }
    $txtPeersStatus.Text = "Fetching..."
    Write-Log "Fetching routing peers (BGP=$doBGP OSPF=$doOSPF) on $($devs.Count) device(s)..."
    $script:ColPeersAll.Clear(); $script:ColPeers.Clear()
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('devs',$devs)
    $rs.SessionStateProxy.SetVariable('doBGP',$doBGP)
    $rs.SessionStateProxy.SetVariable('doOSPF',$doOSPF)
    $rs.SessionStateProxy.SetVariable('allList',$script:ColPeersAll)
    $rs.SessionStateProxy.SetVariable('coll',$script:ColPeers)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('writeTraceFn',${function:Write-Trace})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtPeersStatus)
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m)   { & $writeLogFn $m }
        function Trace($m) { & $writeTraceFn $m }
        function UI($b)    { $Window.Dispatcher.Invoke($b, 'Normal') }
        function GetProp($obj, [string[]]$names) {
            foreach ($n in $names) {
                try {
                    $v = $obj.$n
                    if ($null -ne $v -and ([string]$v).Trim() -ne '') { return [string]$v }
                } catch {}
            }
            return ''
        }
        function FmtSecs([string]$s) {
            if ([string]::IsNullOrWhiteSpace($s) -or -not ($s -match '^\d+$')) { return $s }
            $secs = [int]$s
            $ts = [TimeSpan]::FromSeconds($secs)
            if ($ts.Days -gt 0) { return ("{0}d {1:00}:{2:00}:{3:00}" -f $ts.Days,$ts.Hours,$ts.Minutes,$ts.Seconds) }
            return ("{0:00}:{1:00}:{2:00}" -f $ts.Hours,$ts.Minutes,$ts.Seconds)
        }
        $total = 0; $withPeers = 0
        foreach ($dev in $devs) {
            $devRows = New-Object 'System.Collections.Generic.List[object]'
            if ($doBGP) {
                try {
                    $resp = Invoke-PANOperation -SkipCertificateCheck `
                                -Command "<show><routing><protocol><bgp><peer/></bgp></protocol></routing></show>" `
                                -Target $dev.Serial
                    $entries = @()
                    try { $entries = @($resp.result.entry | Where-Object { $_ -is [System.Xml.XmlElement] }) } catch {}
                    foreach ($e in $entries) {
                        $peerName = ''
                        try { $peerName = [string]$e.peer } catch {}
                        if (-not $peerName) { try { $peerName = [string]$e.GetAttribute('peer') } catch {} }
                        if (-not $peerName) { $peerName = GetProp $e @('name','peer-name') }
                        $vr = ''
                        try { $vr = [string]$e.vr } catch {}
                        if (-not $vr) { try { $vr = [string]$e.GetAttribute('vr') } catch {} }
                        if (-not $vr) { $vr = GetProp $e @('virtual-router') }
                        $asn  = GetProp $e @('remote-as','peer-as')
                        $addr = GetProp $e @('peer-address','peer-ip')
                        $stat = GetProp $e @('status','state')
                        $dur  = GetProp $e @('status-duration','peer-status-duration','uptime')
                        $devRows.Add([PSCustomObject]@{
                            Hostname = $dev.Hostname
                            VR       = $vr
                            Protocol = 'BGP'
                            PeerName = $peerName
                            PeerAddr = $addr
                            ASNArea  = "AS $asn"
                            State    = $stat
                            Uptime   = FmtSecs $dur
                            Notes    = ''
                        })
                    }
                } catch { Log "  $($dev.Hostname) [BGP] - $($_.Exception.Message)" }
            }
            if ($doOSPF) {
                try {
                    $resp = Invoke-PANOperation -SkipCertificateCheck `
                                -Command "<show><routing><protocol><ospf><neighbor/></ospf></protocol></routing></show>" `
                                -Target $dev.Serial
                    $entries = @()
                    try { $entries = @($resp.result.entry | Where-Object { $_ -is [System.Xml.XmlElement] }) } catch {}
                    foreach ($e in $entries) {
                        $rid  = GetProp $e @('neighbor-router-id','neighbor-id','neighbor')
                        $area = GetProp $e @('area-id','area')
                        $addr = GetProp $e @('neighbor-address','address','peer-address')
                        $stat = GetProp $e @('status','state')
                        $dur  = GetProp $e @('status-duration','dead-time')
                        $vr   = GetProp $e @('virtual-router','vr')
                        $devRows.Add([PSCustomObject]@{
                            Hostname = $dev.Hostname
                            VR       = $vr
                            Protocol = 'OSPF'
                            PeerName = $rid
                            PeerAddr = $addr
                            ASNArea  = "area $area"
                            State    = $stat
                            Uptime   = FmtSecs $dur
                            Notes    = ''
                        })
                    }
                } catch { Log "  $($dev.Hostname) [OSPF] - $($_.Exception.Message)" }
            }
            if ($devRows.Count -gt 0) {
                UI { foreach ($r in $devRows) { $allList.Add($r); $coll.Add($r) } }
                $total += $devRows.Count
                $withPeers += 1
                Log "  $($dev.Hostname) - $($devRows.Count) peer(s)"
            }
        }
        UI {
            $txtStatus.Text = "Done - $total peer(s) across $withPeers / $($devs.Count) device(s)"
            $fetchLock.Busy = $false; $fetchLock.Name = ''
        }
        Log "Peers fetch complete: $total peer(s) on $withPeers device(s)."
    })
    [void]$ps.BeginInvoke()
}
$btnFetchPeers.Add_Click({       Invoke-PeersFetch @($script:DisplayColl | Where-Object Selected) })
$btnFetchPeersAll.Add_Click({    Invoke-PeersFetch @($script:DisplayColl) })
$btnExportPeers.Add_Click({      Export-CollToCSV $script:ColPeersAll 'routing_peers' })
$cbPeersOnlyDown.Add_Checked({   Update-PeersFilter })
$cbPeersOnlyDown.Add_Unchecked({ Update-PeersFilter })

# ── HA config-sync drift ─────────────────────────────────────
# Pulls <show><high-availability><state/></high-availability></show> from each
# device and reports local vs peer sync indicators. PAN-OS does NOT expose a
# running-config checksum directly, so we rely on <running-sync> (synchronized
# / not synchronized) plus content/OS version comparisons (app/threat/SW match).
function Update-DriftFilter {
    $script:ColDrift.Clear()
    $only = $cbDriftOnlyMismatch.IsChecked
    foreach ($r in $script:ColDriftAll) {
        if ($only) {
            $isMatch = ($r.ConfigSync -match '(?i)synchronized' -and
                        $r.AppVerMatch -eq 'yes' -and
                        $r.SwVerMatch  -eq 'yes')
            if ($isMatch) { continue }
        }
        $script:ColDrift.Add($r)
    }
    $txtDriftStatus.Text = "Shown: $($script:ColDrift.Count) / $($script:ColDriftAll.Count) pair(s)"
}

function Invoke-DriftFetch([object[]]$devs) {
    if (-not $devs -or $devs.Count -eq 0) { Write-Log "No devices selected for HA drift."; return }
    if (-not (Begin-Fetch 'HA Drift')) { return }
    $txtDriftStatus.Text = "Checking..."
    Write-Log "Checking HA sync on $($devs.Count) device(s)..."
    $script:ColDriftAll.Clear(); $script:ColDrift.Clear()
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('devs',$devs)
    $rs.SessionStateProxy.SetVariable('allList',$script:ColDriftAll)
    $rs.SessionStateProxy.SetVariable('coll',$script:ColDrift)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtDriftStatus)
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        function GetProp($obj, [string[]]$names) {
            foreach ($n in $names) {
                try {
                    $v = $obj.$n
                    if ($null -ne $v -and ([string]$v).Trim() -ne '') { return [string]$v }
                } catch {}
            }
            return ''
        }
        $checked = 0; $haPairs = 0
        foreach ($dev in $devs) {
            try {
                $resp = Invoke-PANOperation -SkipCertificateCheck `
                            -Command "<show><high-availability><state/></high-availability></show>" `
                            -Target $dev.Serial
                $enabled = ''
                try { $enabled = [string]$resp.result.enabled } catch {}
                if ($enabled -notmatch '(?i)yes|true') {
                    $row = [PSCustomObject]@{
                        Hostname      = $dev.Hostname
                        LocalState    = 'standalone'
                        PeerMgmtIP    = ''
                        PeerState     = ''
                        ConfigSync    = 'n/a (no HA)'
                        StateSync     = ''
                        AppVerMatch   = 'n/a'
                        SwVerMatch    = 'n/a'
                        LocalPriority = ''
                        PeerPriority  = ''
                        Notes         = 'HA not enabled'
                    }
                    UI { $allList.Add($row); $coll.Add($row) }
                    $checked++
                    continue
                }
                $group = $resp.result.group
                $local = $group.'local-info'
                $peer  = $group.'peer-info'
                $configSync = GetProp $group @('running-sync','configuration-synchronization','sync-state')
                if (-not $configSync) { $configSync = '?' }
                $stateSync = GetProp $local @('state-sync')
                $localState = GetProp $local @('state')
                $peerState  = GetProp $peer  @('state')
                $peerIP     = GetProp $peer  @('mgmt-ip','ha1-ipaddr')
                $localPri   = GetProp $local @('priority')
                $peerPri    = GetProp $peer  @('priority')
                $localApp   = GetProp $local @('app-version')
                $peerApp    = GetProp $peer  @('app-version')
                $localSw    = GetProp $local @('build-rel','version')
                $peerSw     = GetProp $peer  @('build-rel','version')
                $appMatch = if ($localApp -and $peerApp) { if ($localApp -eq $peerApp) { 'yes' } else { 'NO' } } else { '?' }
                $swMatch  = if ($localSw  -and $peerSw)  { if ($localSw  -eq $peerSw ) { 'yes' } else { 'NO' } } else { '?' }
                $notes = @()
                if ($configSync -notmatch '(?i)synchronized') { $notes += "config NOT synced" }
                if ($appMatch -eq 'NO') { $notes += "app-ver drift (L:$localApp / P:$peerApp)" }
                if ($swMatch  -eq 'NO') { $notes += "SW drift (L:$localSw / P:$peerSw)" }
                $row = [PSCustomObject]@{
                    Hostname      = $dev.Hostname
                    LocalState    = $localState
                    PeerMgmtIP    = $peerIP
                    PeerState     = $peerState
                    ConfigSync    = $configSync
                    StateSync     = $stateSync
                    AppVerMatch   = $appMatch
                    SwVerMatch    = $swMatch
                    LocalPriority = $localPri
                    PeerPriority  = $peerPri
                    Notes         = ($notes -join '; ')
                }
                UI { $allList.Add($row); $coll.Add($row) }
                $checked++; $haPairs++
                Log "  $($dev.Hostname) - sync=$configSync app=$appMatch sw=$swMatch"
            } catch { Log "  $($dev.Hostname) - $($_.Exception.Message)" }
        }
        UI {
            $txtStatus.Text = "Done - $checked checked, $haPairs HA-enabled"
            $fetchLock.Busy = $false; $fetchLock.Name = ''
        }
        Log "HA Drift check complete: $checked device(s), $haPairs HA-enabled."
    })
    [void]$ps.BeginInvoke()
}
$btnFetchDrift.Add_Click({          Invoke-DriftFetch @($script:DisplayColl | Where-Object Selected) })
$btnFetchDriftAll.Add_Click({       Invoke-DriftFetch @($script:DisplayColl) })
$btnExportDrift.Add_Click({         Export-CollToCSV $script:ColDriftAll 'ha_drift' })
$cbDriftOnlyMismatch.Add_Checked({   Update-DriftFilter })
$cbDriftOnlyMismatch.Add_Unchecked({ Update-DriftFilter })

# ── GP Gateway stats ─────────────────────────────────────────
# Per-DC firewall: list of gateways with current/max user counts and
# tunnel-mode breakdown. Uses two commands per FW for portability since the
# <statistics/> variant is version-dependent:
#   - <show><global-protect-gateway><gateway/></global-protect-gateway></show>
#       for the gateway list + max-user / tunnel info
#   - <show><global-protect-gateway><current-user/></global-protect-gateway></show>
#       for the active-user list, grouped by <gateway> field for active counts
# Auto-restricts to data-center firewalls like the GP Users tab.
function Invoke-GWFetch([object[]]$devs) {
    if (-not $devs -or $devs.Count -eq 0) { Write-Log "No DC gateways selected."; return }
    if (-not (Begin-Fetch 'GP Gateways')) { return }
    $txtGWStatus.Text = "Fetching..."
    Write-Log "Fetching GP gateway stats from $($devs.Count) DC firewall(s)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('devs',$devs)
    $rs.SessionStateProxy.SetVariable('coll',$script:ColGW)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtGWStatus)
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        function GetProp($obj, [string[]]$names) {
            foreach ($n in $names) {
                try {
                    $v = $obj.$n
                    if ($null -ne $v -and ([string]$v).Trim() -ne '') { return [string]$v }
                } catch {}
            }
            return ''
        }
        UI { $coll.Clear() }
        $totalRows = 0
        foreach ($dev in $devs) {
            try {
                # Active users per gateway (count grouped by .gateway field)
                $activeByGW = @{}
                $sslByGW    = @{}
                $ipsecByGW  = @{}
                try {
                    $cur = Invoke-PANOperation -SkipCertificateCheck `
                                -Command "<show><global-protect-gateway><current-user/></global-protect-gateway></show>" `
                                -Target $dev.Serial
                    $userEntries = @($cur.result.entry | Where-Object {
                        $_ -is [System.Xml.XmlElement] -and ([string]$_.username).Trim() -ne ''
                    })
                    foreach ($u in $userEntries) {
                        $gn = GetProp $u @('gateway','gateway-name')
                        if (-not $gn) { $gn = '(unknown)' }
                        if (-not $activeByGW.ContainsKey($gn)) { $activeByGW[$gn] = 0; $sslByGW[$gn] = 0; $ipsecByGW[$gn] = 0 }
                        $activeByGW[$gn]++
                        $tt = GetProp $u @('tunnel-type')
                        if ($tt -match '(?i)ssl') { $sslByGW[$gn]++ }
                        if ($tt -match '(?i)ipsec') { $ipsecByGW[$gn]++ }
                    }
                } catch { Log "  $($dev.Hostname) - current-user error: $($_.Exception.Message)" }

                # Configured gateways: name, max-user, tunnel-name
                $gwEntries = @()
                try {
                    $gw = Invoke-PANOperation -SkipCertificateCheck `
                                -Command "<show><global-protect-gateway><gateway/></global-protect-gateway></show>" `
                                -Target $dev.Serial
                    $gwEntries = @($gw.result.entry | Where-Object { $_ -is [System.Xml.XmlElement] })
                } catch { Log "  $($dev.Hostname) - gateway list error: $($_.Exception.Message)" }

                if ($gwEntries.Count -eq 0) {
                    # Fall back to synthesizing rows from active users only
                    if ($activeByGW.Count -eq 0) {
                        Log "  $($dev.Hostname) - no gateways and no active users"
                        continue
                    }
                    $rows = New-Object 'System.Collections.Generic.List[object]'
                    foreach ($k in $activeByGW.Keys) {
                        $rows.Add([PSCustomObject]@{
                            Hostname    = $dev.Hostname
                            GatewayName = $k
                            TunnelName  = ''
                            ActiveUsers = $activeByGW[$k]
                            MaxUsers    = ''
                            SSLUsers    = $sslByGW[$k]
                            IPsecUsers  = $ipsecByGW[$k]
                            Notes       = 'no <gateway/> data; counts from current-user'
                        })
                    }
                    UI { foreach ($r in $rows) { $coll.Add($r) } }
                    $totalRows += $rows.Count
                    continue
                }

                $rows = New-Object 'System.Collections.Generic.List[object]'
                foreach ($e in $gwEntries) {
                    $gn   = GetProp $e @('gateway-name','name')
                    $tnl  = GetProp $e @('tunnel-name','tunnel')
                    $maxu = GetProp $e @('max-user','total-licensed')
                    $act  = if ($activeByGW.ContainsKey($gn)) { $activeByGW[$gn] } else { 0 }
                    $ssl  = if ($sslByGW.ContainsKey($gn))    { $sslByGW[$gn]    } else { 0 }
                    $ips  = if ($ipsecByGW.ContainsKey($gn))  { $ipsecByGW[$gn]  } else { 0 }
                    $rows.Add([PSCustomObject]@{
                        Hostname    = $dev.Hostname
                        GatewayName = $gn
                        TunnelName  = $tnl
                        ActiveUsers = $act
                        MaxUsers    = $maxu
                        SSLUsers    = $ssl
                        IPsecUsers  = $ips
                        Notes       = ''
                    })
                }
                if ($rows.Count -gt 0) {
                    UI { foreach ($r in $rows) { $coll.Add($r) } }
                    $totalRows += $rows.Count
                    Log "  $($dev.Hostname) - $($rows.Count) gateway(s)"
                }
            } catch { Log "  $($dev.Hostname) - $($_.Exception.Message)" }
        }
        UI {
            $txtStatus.Text = "Done - $totalRows gateway row(s) across $($devs.Count) DC firewall(s)"
            $fetchLock.Busy = $false; $fetchLock.Name = ''
        }
        Log "GP Gateway fetch complete: $totalRows row(s)."
    })
    [void]$ps.BeginInvoke()
}
$btnFetchGW.Add_Click({
    $sel = Get-DCDevices @($script:DisplayColl | Where-Object Selected)
    if ($sel.Count -eq 0) { Write-Log "No DC gateways in selection."; return }
    Invoke-GWFetch $sel
})
$btnFetchGWAll.Add_Click({
    $dc = Get-DCDevices @($script:DisplayColl)
    if ($dc.Count -eq 0) { Write-Log "No DC gateways loaded."; return }
    Invoke-GWFetch $dc
})
$btnExportGW.Add_Click({ Export-CollToCSV $script:ColGW 'gp_gateways' })

# ── test security-policy-match ───────────────────────────────
# <test><security-policy-match>...</security-policy-match></test>
# Required: source, destination, destination-port, protocol (integer).
# Optional: application, source-user, category, from, to.
# Response: <result><rules><entry name="rule"><index/><action/>...</entry></rules>
# Empty <rules/> means implicit deny.
function Invoke-PMFetch([object[]]$devs) {
    if (-not $devs -or $devs.Count -eq 0) { Write-Log "No devices selected for policy match."; return }
    $src   = $txtPMSrc.Text.Trim()
    $dst   = $txtPMDst.Text.Trim()
    $dport = $txtPMDPort.Text.Trim()
    $proto = $txtPMProto.Text.Trim()
    $app   = $txtPMApp.Text.Trim()
    $usr   = $txtPMUser.Text.Trim()
    $from  = $txtPMFrom.Text.Trim()
    $to    = $txtPMTo.Text.Trim()
    if (-not $src -or -not $dst -or -not $dport -or -not $proto) {
        [System.Windows.MessageBox]::Show("Src, Dst, DPort, and Proto (integer) are required.", "Missing", "OK", "Information") | Out-Null
        return
    }
    if ($proto -notmatch '^\d+$') {
        # Allow tcp/udp/icmp shortcuts
        $protoMap = @{ tcp = '6'; udp = '17'; icmp = '1' }
        if ($protoMap.ContainsKey($proto.ToLower())) { $proto = $protoMap[$proto.ToLower()] }
        else { [System.Windows.MessageBox]::Show("Proto must be an integer (6=tcp, 17=udp, 1=icmp).", "Bad proto", "OK", "Warning") | Out-Null; return }
    }
    function Esc($v) { $v.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;') }
    $body = "<source>$(Esc $src)</source><destination>$(Esc $dst)</destination><destination-port>$(Esc $dport)</destination-port><protocol>$(Esc $proto)</protocol>"
    if ($app)  { $body += "<application>$(Esc $app)</application>" }
    if ($usr)  { $body += "<source-user>$(Esc $usr)</source-user>" }
    if ($from) { $body += "<from>$(Esc $from)</from>" }
    if ($to)   { $body += "<to>$(Esc $to)</to>" }
    if ($cbPMShowAll.IsChecked) { $body += "<show-all>yes</show-all>" }
    $cmd = "<test><security-policy-match>$body</security-policy-match></test>"
    if (-not (Begin-Fetch 'Policy Match')) { return }
    $txtPMStatus.Text = "Testing..."
    Write-Log "Policy match: src=$src dst=$dst dport=$dport proto=$proto app=$app user=$usr on $($devs.Count) device(s)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('devs',$devs)
    $rs.SessionStateProxy.SetVariable('cmd',$cmd)
    $rs.SessionStateProxy.SetVariable('coll',$script:ColPM)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtPMStatus)
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        function GetProp($obj, [string[]]$names) {
            foreach ($n in $names) {
                try {
                    $v = $obj.$n
                    if ($null -eq $v) { continue }
                    # An element with children (e.g. <category><member>..</member></category>)
                    # or an empty element stringifies to "System.Xml.XmlElement" — pull text instead.
                    if ($v -is [System.Xml.XmlElement]) {
                        $t = if ($v.member) { (@($v.member) | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ }) -join ', ' }
                             else { ([string]$v.InnerText).Trim() }
                        if ($t -ne '') { return $t }
                    } else {
                        $s = ([string]$v).Trim()
                        if ($s -ne '') { return $s }
                    }
                } catch {}
            }
            return ''
        }
        UI { $coll.Clear() }
        $matched = 0; $noMatch = 0
        foreach ($dev in $devs) {
            try {
                $resp = Invoke-PANOperation -SkipCertificateCheck -Command $cmd -Target $dev.Serial
                if ($resp.status -ne 'success') {
                    $err = ''
                    try { $err = [string]$resp.msg.line } catch {}
                    if (-not $err) { try { $err = [string]$resp.msg } catch {} }
                    UI { $coll.Add([PSCustomObject]@{
                        Hostname = $dev.Hostname; Idx=''; RuleName=''; Action='ERROR'; FromZone=''; ToZone=''; App=''; Category=''; Terminal=''
                        Notes = "API error: $err"
                    }) }
                    Log "  $($dev.Hostname) - error: $err"
                    continue
                }
                $entries = @()
                try { $entries = @($resp.result.rules.entry | Where-Object { $_ -is [System.Xml.XmlElement] }) } catch {}
                if ($entries.Count -eq 0) {
                    UI { $coll.Add([PSCustomObject]@{
                        Hostname = $dev.Hostname; Idx=''; RuleName='(no match)'; Action='implicit deny'
                        FromZone=''; ToZone=''; App=''; Category=''; Terminal=''
                        Notes = 'no security rule matched; default deny'
                    }) }
                    $noMatch++
                    Log "  $($dev.Hostname) - no match (implicit deny)"
                    continue
                }
                $rows = New-Object 'System.Collections.Generic.List[object]'
                foreach ($e in $entries) {
                    $rname = ''
                    try { $rname = [string]$e.name } catch {}
                    if (-not $rname) { try { $rname = [string]$e.GetAttribute('name') } catch {} }
                    $rows.Add([PSCustomObject]@{
                        Hostname = $dev.Hostname
                        Idx      = GetProp $e @('index')
                        RuleName = $rname
                        Action   = GetProp $e @('action')
                        FromZone = GetProp $e @('from')
                        ToZone   = GetProp $e @('to')
                        App      = GetProp $e @('application','app')
                        Category = GetProp $e @('category')
                        Terminal = GetProp $e @('terminal')
                        Notes    = ''
                    })
                }
                UI { foreach ($r in $rows) { $coll.Add($r) } }
                $matched += $rows.Count
                Log "  $($dev.Hostname) - $($rows.Count) match(es)"
            } catch { Log "  $($dev.Hostname) - $($_.Exception.Message)" }
        }
        UI {
            $txtStatus.Text = "Done - $matched match(es), $noMatch no-match (of $($devs.Count) device(s))"
            $fetchLock.Busy = $false; $fetchLock.Name = ''
        }
        Log "Policy match complete: $matched match row(s), $noMatch no-match."
    })
    [void]$ps.BeginInvoke()
}
$btnRunPM.Add_Click({    Invoke-PMFetch @($script:DisplayColl | Where-Object Selected) })
$btnRunPMAll.Add_Click({ Invoke-PMFetch @($script:DisplayColl) })
$btnExportPM.Add_Click({ Export-CollToCSV $script:ColPM 'policy_match' })

# ── Force HA failover (Suspend / Resume) ─────────────────────
function Invoke-HAStateChange([string]$state, [string]$verb, [string]$dialogWarn) {
    $sel = @($script:DisplayColl | Where-Object Selected)
    if ($sel.Count -eq 0) { Write-Log "No devices selected."; return }
    $names = ($sel | ForEach-Object { $_.Hostname }) -join ', '
    $msg = "$verb HA on $($sel.Count) device(s)?`n`n$names`n`n$dialogWarn"
    if ([System.Windows.MessageBox]::Show($msg, "Confirm: $verb HA", "YesNo", "Warning") -ne 'Yes') { return }
    if (-not (Begin-Fetch "HA $verb")) { return }
    Write-Log "$verb HA on $($sel.Count) device(s)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('sel',$sel)
    $rs.SessionStateProxy.SetVariable('stateOp',$state)
    $rs.SessionStateProxy.SetVariable('verb',$verb)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b) { $Window.Dispatcher.Invoke($b, 'Normal') }
        foreach ($dev in $sel) {
            try {
                $cmd = "<request><high-availability><state><$stateOp/></state></high-availability></request>"
                $r = Invoke-PANOperation -SkipCertificateCheck -Command $cmd -Target $dev.Serial
                Log "  $($dev.Hostname) [$verb] -> $($r.status)"
            } catch { Log "  $($dev.Hostname) [$verb] - $($_.Exception.Message)" }
        }
        UI { $fetchLock.Busy = $false; $fetchLock.Name = '' }
        Log "$verb HA complete."
    })
    [void]$ps.BeginInvoke()
}
$btnSuspendHA.Add_Click({
    Invoke-HAStateChange 'suspend' 'Suspend' `
        "Suspending the ACTIVE peer triggers immediate failover to the passive peer."
})
$btnResumeHA.Add_Click({
    Invoke-HAStateChange 'functional' 'Resume' `
        "Returns the suspended peer to functional state. It will rejoin per HA election rules."
})

# ── Bulk Commit ──────────────────────────────────────────────
$btnCommit.Add_Click({
    $sel = @($script:DisplayColl | Where-Object Selected)
    if ($sel.Count -eq 0) { Write-Log "No devices selected."; return }
    if ([System.Windows.MessageBox]::Show("Commit candidate config on $($sel.Count) device(s)?`n`nThis activates ALL pending (uncommitted) changes on each selected firewall's local config. On HA pairs the running config then syncs to the peer. Continue?", "Confirm Commit", "YesNo", "Warning") -ne 'Yes') { return }
    if (-not (Begin-Fetch 'Commit')) { return }
    Write-Log "Committing on $($sel.Count) device(s)..."
    $btnCommit.IsEnabled = $false
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('sel',$sel)
    $rs.SessionStateProxy.SetVariable('Window',$Window)
    $rs.SessionStateProxy.SetVariable('btnCommit',$btnCommit)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        Import-Module pan-power -ErrorAction SilentlyContinue
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        $ok = 0; $fail = 0
        foreach ($dev in $sel) {
            try {
                $r = Invoke-PANCommit -Target $dev.Serial -SkipCertificateCheck
                if ($r.status -eq 'success') {
                    $ok++
                    Log "  $($dev.Hostname) - commit OK (job $($r.result.job))"
                } else {
                    $fail++
                    Log "  $($dev.Hostname) - commit failed: $($r.msg)"
                }
            } catch { $fail++; Log "  $($dev.Hostname) - $($_.Exception.Message)" }
        }
        UI {
            $btnCommit.IsEnabled = $true
            $fetchLock.Busy = $false; $fetchLock.Name = ''
        }
        Log "Commit batch done: OK=$ok Fail=$fail"
    })
    [void]$ps.BeginInvoke()
})

# ── Rule Miner ───────────────────────────────────────────────
# Mines traffic logs from Panorama for one broad rule, aggregates flows by
# destination+app/port, and generates Panorama set CLI for specific rules with
# source-user known-user. CLI is copy/paste only — nothing is pushed.
# Raw XML API (keygen + type=log / type=config) — does NOT use pan-power, but
# still honors the FetchLock single-flight gate for UI consistency.

function Invoke-RMLoadRules {
    $dg = $txtRMDG.Text.Trim()
    if ($dg -eq '') { Write-Log "[RuleMiner] Enter a device-group name first."; return }
    if (-not $script:PanCred.User -or -not $script:PanCred.Pass) { Write-Log "[RuleMiner] Not connected - connect to Panorama first."; return }
    if (-not (Begin-Fetch 'RM-LoadRules')) { return }
    $txtRMStatus.Text = "Loading rules..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('panIp',   $script:PanCred.IP)
    $rs.SessionStateProxy.SetVariable('panUser', $script:PanCred.User)
    $rs.SessionStateProxy.SetVariable('panPass', $script:PanCred.Pass)
    $rs.SessionStateProxy.SetVariable('dg',      $dg)
    $rs.SessionStateProxy.SetVariable('ruleInfo',$script:RMRuleInfo)
    $rs.SessionStateProxy.SetVariable('Window',  $Window)
    $rs.SessionStateProxy.SetVariable('cbRule',  $cbRMRule)
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtRMStatus)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        function Log($m) { & $writeLogFn $m }
        function UI($b)  { $Window.Dispatcher.Invoke($b, 'Normal') }
        $prevSsl = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [SSLAcceptAll]::Callback
        try {
            $kUri = 'https://' + $panIp + '/api/?type=keygen&user=' + [uri]::EscapeDataString($panUser) + '&password=' + [uri]::EscapeDataString($panPass)
            $key  = [string](Invoke-RestMethod -Uri $kUri -Method GET -TimeoutSec 20 -ErrorAction Stop).response.result.key
            if (-not $key) { throw "keygen returned no key" }
            $xpath = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='$dg']/pre-rulebase/security/rules"
            $uri = 'https://' + $panIp + '/api/?type=config&action=get&xpath=' + [uri]::EscapeDataString($xpath) + '&key=' + [uri]::EscapeDataString($key)
            $r = Invoke-RestMethod -Uri $uri -Method GET -TimeoutSec 30 -ErrorAction Stop
            if ([string]$r.response.status -ne 'success') { throw "config get failed: $([string]$r.response.OuterXml)" }
            $entries = @()
            try { $entries = @($r.response.result.rules.entry | Where-Object { $_ -is [System.Xml.XmlElement] }) } catch {}
            if ($entries.Count -eq 0) {
                # Help the user: list available device-groups
                $dgUri = 'https://' + $panIp + '/api/?type=config&action=get&xpath=' + [uri]::EscapeDataString("/config/devices/entry[@name='localhost.localdomain']/device-group") + '&key=' + [uri]::EscapeDataString($key)
                $names = @()
                try { $names = @((Invoke-RestMethod -Uri $dgUri -TimeoutSec 30).response.result.'device-group'.entry | ForEach-Object { [string]$_.name }) } catch {}
                Log "[RuleMiner] No pre-rulebase rules found in device-group '$dg'. Available device-groups: $($names -join ', ')"
                UI { $txtStatus.Text = "0 rules - check device-group name (see log)"; $fetchLock.Busy=$false; $fetchLock.Name='' }
                return
            }
            $ruleInfo.Clear()
            $list = New-Object 'System.Collections.Generic.List[string]'
            foreach ($e in $entries) {
                $n = [string]$e.name
                $from = @(); $to = @()
                try { $from = @($e.from.member | ForEach-Object { [string]$_ }) } catch {}
                try { $to   = @($e.to.member   | ForEach-Object { [string]$_ }) } catch {}
                $ruleInfo[$n] = @{ From = $from; To = $to; Action = [string]$e.action }
                $list.Add($n)
            }
            UI {
                $cbRule.ItemsSource = $list
                $txtStatus.Text = "$($list.Count) rules loaded from '$dg'"
                $fetchLock.Busy=$false; $fetchLock.Name=''
            }
            Log "[RuleMiner] Loaded $($list.Count) pre-rulebase rules from device-group '$dg'."
        } catch {
            $msg = $_.Exception.Message
            Log "[RuleMiner] Load Rules failed: $msg"
            UI { $txtStatus.Text = "Load failed - see log"; $fetchLock.Busy=$false; $fetchLock.Name='' }
        } finally {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $prevSsl
        }
    })
    [void]$ps.BeginInvoke()
}

function Invoke-RMFetch {
    $rule = $cbRMRule.Text.Trim()
    if ($rule -eq '') { Write-Log "[RuleMiner] Pick or type the broad rule name first."; return }
    if (-not $script:PanCred.User -or -not $script:PanCred.Pass) { Write-Log "[RuleMiner] Not connected - connect to Panorama first."; return }
    $days = 7;     if ($txtRMDays.Text.Trim() -match '^\d+$') { $days = [int]$txtRMDays.Text.Trim() }
    if ($days -lt 1) { $days = 1 }
    $cap  = 20000; if ($txtRMCap.Text.Trim()  -match '^\d+$') { $cap  = [int]$txtRMCap.Text.Trim() }
    if ($cap -lt 100)    { $cap = 100 }
    if ($cap -gt 100000) { $cap = 100000 }
    # Matching options — read on the UI thread (runspaces cannot touch controls)
    $matchObj    = [bool]$cbRMMatchObj.IsChecked
    $resolveLdap = [bool]$cbRMResolveLdap.IsChecked
    $transitive  = [bool]$cbRMTransitive.IsChecked
    $userMax = 50; if ($txtRMUserMax.Text.Trim() -match '^\d+$') { $userMax = [int]$txtRMUserMax.Text.Trim() }
    if ($userMax -lt 1) { $userMax = 1 }
    $coverPct = 80; if ($txtRMCoverPct.Text.Trim() -match '^\d+$') { $coverPct = [int]$txtRMCoverPct.Text.Trim() }
    if ($coverPct -lt 1) { $coverPct = 1 }; if ($coverPct -gt 100) { $coverPct = 100 }
    $coverFrac = $coverPct / 100.0
    if (-not (Begin-Fetch 'RM-Mine')) { return }
    $txtRMStatus.Text = "Mining..."
    Write-Log "[RuleMiner] Mining traffic logs: rule='$rule' days=$days cap=$cap (match-obj=$matchObj ldap=$resolveLdap cover=$coverPct% userMax=$userMax)..."
    $rs = [runspacefactory]::CreateRunspace(); $rs.ApartmentState='STA'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('panIp',   $script:PanCred.IP)
    $rs.SessionStateProxy.SetVariable('panUser', $script:PanCred.User)
    $rs.SessionStateProxy.SetVariable('panPass', $script:PanCred.Pass)
    $rs.SessionStateProxy.SetVariable('rule',    $rule)
    $rs.SessionStateProxy.SetVariable('days',    $days)
    $rs.SessionStateProxy.SetVariable('cap',     $cap)
    $rs.SessionStateProxy.SetVariable('coll',    $script:ColRM)
    $rs.SessionStateProxy.SetVariable('Window',  $Window)
    $rs.SessionStateProxy.SetVariable('txtStatus',$txtRMStatus)
    $rs.SessionStateProxy.SetVariable('writeLogFn',${function:Write-Log})
    $rs.SessionStateProxy.SetVariable('writeTraceFn',${function:Write-Trace})
    $rs.SessionStateProxy.SetVariable('fetchLock',$script:FetchLock)
    $rs.SessionStateProxy.SetVariable('matchObj',    $matchObj)
    $rs.SessionStateProxy.SetVariable('resolveLdap', $resolveLdap)
    $rs.SessionStateProxy.SetVariable('transitive',  $transitive)
    $rs.SessionStateProxy.SetVariable('userMax',     $userMax)
    $rs.SessionStateProxy.SetVariable('coverFrac',   $coverFrac)
    $rs.SessionStateProxy.SetVariable('rmTags',    $script:RMTags)
    $rs.SessionStateProxy.SetVariable('rmSvc',     $script:RMSvc)
    $rs.SessionStateProxy.SetVariable('rmGroups',  $script:RMGroups)
    $rs.SessionStateProxy.SetVariable('rmObjTags', $script:RMObjTags)
    $rs.SessionStateProxy.SetVariable('dgRM',      $dgRM)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript({
        function Log($m)   { & $writeLogFn $m }
        function Trace($m) { & $writeTraceFn $m }
        function UI($b)    { $Window.Dispatcher.Invoke($b, 'Normal') }
        # ── Address-object / LDAP matching helpers (run inside this runspace) ──
        $ugCache = @{}; $gSamCache = @{}; $groupPredCache = @{}; $gSizeCache = @{}
        $predByName = @{}; $groupByName = @{}
        $hostIndex = @{}   # uint32 IP -> object name, for O(1) exact /32 host match
        $netPreds  = New-Object 'System.Collections.Generic.List[object]'   # only CIDR(/<32) + ranges, scanned for containment
        $netbios = [string]$env:USERDOMAIN
        function Conv-IP([string]$ip) {
            $o = ([string]$ip).Split('.'); if ($o.Count -ne 4) { return $null }
            $v = [uint64]0
            foreach ($p in $o) {
                $n = 0; if (-not [int]::TryParse($p, [ref]$n)) { return $null }
                if ($n -lt 0 -or $n -gt 255) { return $null }
                $v = ($v * 256) + $n   # multiply avoids PowerShell -shl type/overflow quirks
            }
            return [uint32]$v
        }
        function Parse-Addr($e) {
            $name = [string]$e.name
            if ($e.'ip-netmask') {
                $val = [string]$e.'ip-netmask'; $base = $val; $prefix = 32
                if ($val -match '^(.+?)/(\d+)$') { $base = $matches[1]; $prefix = [int]$matches[2] }
                $bi = Conv-IP $base; if ($null -eq $bi) { return $null }
                if ($prefix -lt 0 -or $prefix -gt 32) { return $null }
                # 4294967295 = 0xFFFFFFFF as decimal — the hex literal is parsed as int -1 and breaks the [uint64] cast
                $hostBits = 32 - $prefix
                $mask = [uint32]((([uint64]4294967295) -shl $hostBits) -band 4294967295)
                return [pscustomobject]@{ Name=$name; Kind='net'; Net=([uint32]($bi -band $mask)); Mask=$mask; Prefix=$prefix }
            } elseif ($e.'ip-range') {
                $val = [string]$e.'ip-range'
                if ($val -match '^(.+?)-(.+)$') {
                    $s = Conv-IP $matches[1].Trim(); $en = Conv-IP $matches[2].Trim()
                    if ($null -ne $s -and $null -ne $en) { return [pscustomobject]@{ Name=$name; Kind='range'; Start=$s; End=$en } }
                }
                return $null
            }
            return $null   # fqdn / other kinds: skip for IP matching
        }
        function Addr-Matches($pred, [uint32]$ip) {
            if ($pred.Kind -eq 'net')   { return (($ip -band $pred.Mask) -eq $pred.Net) }
            if ($pred.Kind -eq 'range') { return ($ip -ge $pred.Start -and $ip -le $pred.End) }
            return $false
        }
        function Best-Object([uint32]$ip) {
            if ($hostIndex.ContainsKey($ip)) { return [pscustomobject]@{ Name=$hostIndex[$ip]; Kind='net'; Prefix=32 } }
            $best = $null; $bestScore = -1
            foreach ($p in $netPreds) {   # only non-/32 nets + ranges
                if (-not (Addr-Matches $p $ip)) { continue }
                $score = if ($p.Kind -eq 'net') { $p.Prefix } else { 0 }
                if ($score -gt $bestScore) { $bestScore = $score; $best = $p }
            }
            return $best
        }
        function Resolve-GroupPreds([string]$gname, $seen) {
            if ($groupPredCache.ContainsKey($gname)) { return $groupPredCache[$gname] }
            if ($seen -contains $gname) { return @() }
            $seen2 = $seen + $gname
            $res = New-Object 'System.Collections.Generic.List[object]'
            $gd = $groupByName[$gname]
            if ($gd) {
                foreach ($m in $gd.Members) {
                    if ($predByName.ContainsKey($m)) { $res.Add($predByName[$m]) }
                    elseif ($groupByName.ContainsKey($m)) { foreach ($p in (Resolve-GroupPreds $m $seen2)) { $res.Add($p) } }
                }
            }
            $arr = @($res.ToArray()); $groupPredCache[$gname] = $arr; return $arr
        }
        function Sam-From-User([string]$u) {
            $u = ([string]$u).Trim(); if ($u -eq '') { return $null }
            if ($u.Contains('\'))      { $u = $u.Substring($u.IndexOf('\')+1) }
            elseif ($u.Contains('@'))  { $u = $u.Substring(0, $u.IndexOf('@')) }
            return $u
        }
        function Get-UserGroups([string]$sam) {
            if ($ugCache.ContainsKey($sam)) { return $ugCache[$sam] }
            $groups = @()
            try {
                $ds = [adsisearcher]"(&(objectClass=user)(sAMAccountName=$sam))"
                [void]$ds.PropertiesToLoad.Add('distinguishedName')
                [void]$ds.PropertiesToLoad.Add('memberOf')
                $u = $ds.FindOne()
                if ($u) {
                    if ($transitive) {
                        $udn = [string]$u.Properties['distinguishedname'][0]
                        $gs = [adsisearcher]"(member:1.2.840.113556.1.4.1941:=$udn)"
                        [void]$gs.PropertiesToLoad.Add('distinguishedName'); $gs.PageSize = 500
                        foreach ($g in $gs.FindAll()) { $groups += [string]$g.Properties['distinguishedname'][0] }
                    } else {
                        foreach ($g in $u.Properties['memberof']) { $groups += [string]$g }
                    }
                }
            } catch { }
            $ugCache[$sam] = $groups; return $groups
        }
        function Group-Sam([string]$dn) {
            if ($gSamCache.ContainsKey($dn)) { return $gSamCache[$dn] }
            $sam = $null
            try {
                $gs = [adsisearcher]"(distinguishedName=$dn)"
                [void]$gs.PropertiesToLoad.Add('sAMAccountName')
                $g = $gs.FindOne()
                if ($g -and $g.Properties['samaccountname'].Count) { $sam = [string]$g.Properties['samaccountname'][0] }
            } catch { }
            if (-not $sam -and $dn -match '^CN=([^,]+)') { $sam = $matches[1] }
            $gSamCache[$dn] = $sam; return $sam
        }
        # Direct member count for a group, capped (SizeLimit) so huge groups return quickly.
        # Returns the count (== cap means "at least cap"), or -1 on error.
        function Group-MemberCount([string]$dn, [int]$cap) {
            if ($gSizeCache.ContainsKey($dn)) { return $gSizeCache[$dn] }
            $n = -1
            try {
                # Count TRANSITIVE user members (in-chain) so nested-populated groups are sized correctly,
                # not just direct members. SizeLimit caps it so huge groups return quickly.
                $f = $dn -replace '\\','\5c' -replace '\(','\28' -replace '\)','\29' -replace '\*','\2a'
                $gs = [adsisearcher]"(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=$f))"
                if ($cap -gt 0) { $gs.SizeLimit = $cap }
                [void]$gs.PropertiesToLoad.Add('distinguishedName')
                $n = @($gs.FindAll()).Count
            } catch { $n = -1 }
            $gSizeCache[$dn] = $n; return $n
        }
        $prevSsl = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [SSLAcceptAll]::Callback
        try {
            $kUri = 'https://' + $panIp + '/api/?type=keygen&user=' + [uri]::EscapeDataString($panUser) + '&password=' + [uri]::EscapeDataString($panPass)
            $key  = [string](Invoke-RestMethod -Uri $kUri -Method GET -TimeoutSec 20 -ErrorAction Stop).response.result.key
            if (-not $key) { throw "keygen returned no key" }
            $keyEnc = [uri]::EscapeDataString($key)
            $since  = (Get-Date).AddDays(-$days).ToString('yyyy/MM/dd HH:mm:ss')
            $query  = "(rule eq '$rule') and (receive_time geq '$since')"
            $qEnc   = [uri]::EscapeDataString($query)

            # ── Fetch SHARED address objects + groups (for matching) and existing tags/services (for reuse) ──
            $addrPreds = New-Object 'System.Collections.Generic.List[object]'
            $groupDefs = New-Object 'System.Collections.Generic.List[object]'
            $rmTags.Clear(); $rmSvc.Clear(); $rmGroups.Clear(); $rmObjTags.Clear()
            if ($matchObj) {
                try {
                    $aUri = 'https://' + $panIp + '/api/?type=config&action=get&xpath=' + [uri]::EscapeDataString('/config/shared/address') + '&key=' + $keyEnc
                    $ar = Invoke-RestMethod -Uri $aUri -Method GET -TimeoutSec 30 -ErrorAction Stop
                    $aEntries = @(); try { $aEntries = @($ar.response.result.address.entry | Where-Object { $_ -is [System.Xml.XmlElement] }) } catch {}
                    foreach ($e in $aEntries) {
                        $p = Parse-Addr $e
                        if ($p) {
                            $addrPreds.Add($p); $predByName[$p.Name] = $p
                            if ($p.Kind -eq 'net' -and $p.Prefix -eq 32) { if (-not $hostIndex.ContainsKey($p.Net)) { $hostIndex[$p.Net] = $p.Name } }
                            else { $netPreds.Add($p) }
                        }
                        $etags=@(); try { $etags = @($e.tag.member | ForEach-Object { [string]$_ }) } catch {}
                        $rmObjTags[[string]$e.name] = ($etags -join ';')
                    }
                    $gUri = 'https://' + $panIp + '/api/?type=config&action=get&xpath=' + [uri]::EscapeDataString('/config/shared/address-group') + '&key=' + $keyEnc
                    $gr = Invoke-RestMethod -Uri $gUri -Method GET -TimeoutSec 30 -ErrorAction Stop
                    $gEntries = @(); try { $gEntries = @($gr.response.result.'address-group'.entry | Where-Object { $_ -is [System.Xml.XmlElement] }) } catch {}
                    foreach ($e in $gEntries) {
                        $rmGroups[[string]$e.name] = 1   # record every existing group name (static + dynamic) for reuse
                        if ($e.dynamic) { Log "[RuleMiner] skipped dynamic address-group '$([string]$e.name)' (tag-based; not resolvable from config)"; continue }
                        $mem = @(); try { $mem = @($e.static.member | ForEach-Object { [string]$_ }) } catch {}
                        $gd = [pscustomobject]@{ Name=[string]$e.name; Members=$mem }
                        $groupDefs.Add($gd); $groupByName[$gd.Name] = $gd
                    }
                    # Existing shared tags (skip re-creating)
                    $tUri = 'https://' + $panIp + '/api/?type=config&action=get&xpath=' + [uri]::EscapeDataString('/config/shared/tag') + '&key=' + $keyEnc
                    try { $tr = Invoke-RestMethod -Uri $tUri -Method GET -TimeoutSec 30 -ErrorAction Stop
                          foreach ($e in @($tr.response.result.tag.entry | Where-Object { $_ -is [System.Xml.XmlElement] })) { $rmTags[[string]$e.name] = 1 } } catch {}
                    # Existing shared services keyed by proto/port (reuse instead of creating tcp-<port>)
                    $sUri = 'https://' + $panIp + '/api/?type=config&action=get&xpath=' + [uri]::EscapeDataString('/config/shared/service') + '&key=' + $keyEnc
                    try { $sr = Invoke-RestMethod -Uri $sUri -Method GET -TimeoutSec 30 -ErrorAction Stop
                          foreach ($e in @($sr.response.result.service.entry | Where-Object { $_ -is [System.Xml.XmlElement] })) {
                              $sn=[string]$e.name
                              if ($e.protocol.tcp) { $rmSvc["tcp/$([string]$e.protocol.tcp.port)"] = $sn }
                              elseif ($e.protocol.udp) { $rmSvc["udp/$([string]$e.protocol.udp.port)"] = $sn }
                          } } catch {}
                    Log "[RuleMiner] Inventory: $($addrPreds.Count) objects, $($groupDefs.Count) static groups, $($rmGroups.Count) total groups, $($rmTags.Count) tags, $($rmSvc.Count) services (existing items will be reused)."
                } catch {
                    Log "[RuleMiner] Address-object fetch failed - object matching off this run: $($_.Exception.Message)"
                    $matchObj = $false
                }
            }

            # Aggregate: key = dst|dport|proto|app
            $agg = @{}
            $fetched = 0; $page = 0
            while ($fetched -lt $cap) {
                $want = [Math]::Min(5000, $cap - $fetched)
                $uri  = 'https://' + $panIp + "/api/?type=log&log-type=traffic&query=$qEnc&nlogs=$want&dir=backward&skip=$fetched&key=$keyEnc"
                $sub  = Invoke-RestMethod -Uri $uri -Method GET -TimeoutSec 30 -ErrorAction Stop
                if ([string]$sub.response.status -ne 'success') { throw "log query rejected: $([string]$sub.response.OuterXml)" }
                $jobId = [string]$sub.response.result.job
                if (-not $jobId) { throw "no job id returned" }
                # Poll the job
                $entries = $null
                for ($i = 0; $i -lt 90; $i++) {
                    Start-Sleep -Seconds 2
                    $pUri = 'https://' + $panIp + "/api/?type=log&action=get&job-id=$jobId&key=$keyEnc"
                    $pr   = Invoke-RestMethod -Uri $pUri -Method GET -TimeoutSec 30 -ErrorAction Stop
                    $st   = [string]$pr.response.result.job.status
                    if ($st -eq 'FIN') {
                        try { $entries = @($pr.response.result.log.logs.entry | Where-Object { $_ -is [System.Xml.XmlElement] }) } catch { $entries = @() }
                        break
                    }
                }
                if ($null -eq $entries) { throw "log job $jobId did not finish in 180s (page $page)" }
                if ($page -eq 0 -and $entries.Count -eq 0) {
                    Log "[RuleMiner] 0 traffic logs matched. Check: rule name spelling, that traffic logs are forwarded to Panorama, and the Days window."
                }
                foreach ($e in $entries) {
                    $dst   = [string]$e.dst
                    $dport = [string]$e.dport
                    $proto = [string]$e.proto
                    $app   = [string]$e.app
                    $k = "$dst|$dport|$proto|$app"
                    if (-not $agg.ContainsKey($k)) {
                        $agg[$k] = @{
                            Dst=$dst; DPort=$dport; Proto=$proto; App=$app
                            From=[string]$e.from; To=[string]$e.to
                            Count=0; Bytes=[long]0
                            Users   = New-Object 'System.Collections.Generic.HashSet[string]'
                            Sources = New-Object 'System.Collections.Generic.HashSet[string]'
                            Actions = New-Object 'System.Collections.Generic.HashSet[string]'
                        }
                    }
                    $a = $agg[$k]
                    $a.Count++
                    $u = [string]$e.srcuser; if ($u) { [void]$a.Users.Add($u) }
                    $s = [string]$e.src;     if ($s) { [void]$a.Sources.Add($s) }
                    $ac= [string]$e.action;  if ($ac){ [void]$a.Actions.Add($ac) }
                    $b = 0L; [void][long]::TryParse([string]$e.bytes, [ref]$b); $a.Bytes += $b
                }
                $fetched += $entries.Count
                $page++
                UI { $txtStatus.Text = "Fetched $fetched logs ($($agg.Count) unique flows)..." }
                if ($entries.Count -lt $want) { break }   # no more logs available
            }

            # Build sorted rows
            $rows = New-Object 'System.Collections.Generic.List[object]'
            foreach ($a in ($agg.Values | Sort-Object -Property @{Expression={$_.Count}} -Descending)) {
                $users = @($a.Users)   | Sort-Object
                $srcs  = @($a.Sources) | Sort-Object
                $tu = ($users | Select-Object -First 4) -join ', '; if ($users.Count -gt 4) { $tu += " (+$($users.Count-4))" }
                $ts = ($srcs  | Select-Object -First 4) -join ', '; if ($srcs.Count  -gt 4) { $ts += " (+$($srcs.Count-4))" }

                # ── Destination object match (single IP) ──
                $dstObjName=''; $dstObjDisp=''
                if ($matchObj) {
                    $dip = Conv-IP $a.Dst
                    if ($null -ne $dip) { $bo = Best-Object $dip; if ($bo) { $dstObjName=$bo.Name; $dstObjDisp=$bo.Name } }
                }
                # ── Source object / group match (set of IPs) ──
                $srcGroupName=''; $srcDisp=''; $srcObjList=@(); $srcUnmatched=@()
                if ($matchObj -and $srcs.Count -gt 0) {
                    $srcIPs=@(); foreach ($s in $srcs) { $v = Conv-IP $s; if ($null -ne $v) { $srcIPs += $v } }
                    foreach ($s in $srcs) {
                        $v = Conv-IP $s
                        $bo = if ($null -ne $v) { Best-Object $v } else { $null }
                        if ($bo) { $srcObjList += $bo.Name } else { $srcUnmatched += $s }
                    }
                    $srcObjList = @($srcObjList | Select-Object -Unique)
                    $bestG=''; $bestCov=0.0; $bestSize=[int]::MaxValue; $bestHits=0
                    foreach ($g in $groupDefs) {
                        $preds = Resolve-GroupPreds $g.Name @()
                        if ($preds.Count -eq 0 -or $srcIPs.Count -eq 0) { continue }
                        $cov=0; foreach ($v in $srcIPs) { foreach ($p in $preds) { if (Addr-Matches $p $v) { $cov++; break } } }
                        $frac = $cov / [double]$srcIPs.Count
                        if ($frac -ge $coverFrac -and ($frac -gt $bestCov -or ($frac -eq $bestCov -and $preds.Count -lt $bestSize))) {
                            $bestCov=$frac; $bestG=$g.Name; $bestSize=$preds.Count; $bestHits=$cov
                        }
                    }
                    if ($bestG) { $srcGroupName=$bestG; $srcDisp="grp $bestG $bestHits/$($srcIPs.Count)" }
                    elseif ($srcObjList.Count -gt 0) { $srcDisp = "obj x$($srcObjList.Count)" + $(if ($srcUnmatched.Count) { " (+$($srcUnmatched.Count) raw)" } else { '' }) }
                }
                # GP-VPN zone always uses the GP subnets group, regardless of which group the IPs matched (mirrors CLI generation)
                if ([string]$a.From -like '*GP-VPN*') { $srcGroupName='Global Protect Subnets'; $srcDisp='GP-VPN -> Global Protect Subnets' }
                if ([string]$a.To   -like '*GP-VPN*') { $dstObjName ='Global Protect Subnets'; $dstObjDisp='GP-VPN -> Global Protect Subnets' }
                # LDAP user→group resolution is deferred to a second pass (after rows are shown) for speed.
                $userGrpDisp=''; $userGrpCli=''; $userGrpMissing=@()
                $rows.Add([PSCustomObject]@{
                    Sessions    = $a.Count
                    FromZone    = $a.From
                    ToZone      = $a.To
                    Destination = $a.Dst
                    DPort       = $a.DPort
                    Protocol    = $a.Proto
                    App         = $a.App
                    UserCount   = $users.Count
                    TopUsers    = $tu
                    SrcCount    = $srcs.Count
                    TopSources  = $ts
                    GB          = [Math]::Round($a.Bytes / 1GB, 2)
                    DstObj      = $dstObjDisp
                    SrcMatch    = $srcDisp
                    UserGroup   = $userGrpDisp
                    Actions     = (@($a.Actions) -join ', ')
                    AllUsers    = ($users -join ';')   # full lists for CSV export / CLI gen
                    AllSources  = ($srcs  -join ';')
                    DstObject   = $dstObjName          # matched shared object name ('' if none)
                    SrcGroup    = $srcGroupName         # matched address-group name ('' if none)
                    SrcObjects  = ($srcObjList -join ';')
                    SrcUnmatched= ($srcUnmatched -join ';')
                    UserGroupCli= $userGrpCli           # domain\group ('' if none)
                    UserGrpMissing = ($userGrpMissing -join ';')
                })
            }
            # Show flows immediately (object matching done; LDAP still pending)
            UI {
                $coll.Clear()
                foreach ($r in $rows) { $coll.Add($r) }
                $txtStatus.Text = "$($rows.Count) flows" + $(if ($resolveLdap) { " - resolving user groups..." } else { " (rule '$rule', last $days d)" })
            }
            Log "[RuleMiner] $fetched logs -> $($rows.Count) flows shown.$(if ($resolveLdap) { ' Resolving user groups in the background...' } else { '' })"

            # ── Phase 2: deferred LDAP user→group resolution; grid is already visible ──
            if ($resolveLdap) {
                $done=0
                foreach ($row in $rows) {
                    $done++
                    $uc = [int]$row.UserCount
                    if ($uc -gt 0 -and $uc -lt $userMax) {
                        $rusers = @(([string]$row.AllUsers) -split ';' | Where-Object { $_ })
                        $gCount=@{}; $gMembers=@{}
                        foreach ($u in $rusers) {
                            $sam = Sam-From-User $u; if (-not $sam) { continue }
                            foreach ($gdn in (Get-UserGroups $sam)) {
                                if ($gCount.ContainsKey($gdn)) { $gCount[$gdn]++; [void]$gMembers[$gdn].Add($sam) }
                                else { $gCount[$gdn]=1; $gMembers[$gdn]=(New-Object 'System.Collections.Generic.List[string]'); [void]$gMembers[$gdn].Add($sam) }
                            }
                        }
                        $maxMembers = 2 * $rusers.Count
                        $cands = @($gCount.GetEnumerator() | Where-Object { ($_.Value / [double]$rusers.Count) -ge $coverFrac } | Sort-Object -Property Value -Descending)
                        $chosen=''; $chosenN=0; $tooBig=$false
                        foreach ($c in $cands) {
                            $sz = Group-MemberCount $c.Key ($maxMembers + 1)
                            if ($sz -ge 0 -and $sz -le $maxMembers) { $chosen=$c.Key; $chosenN=$c.Value; break } else { $tooBig=$true }
                        }
                        if ($chosen -ne '') {
                            $gsam = Group-Sam $chosen
                            if ($gsam) {
                                $row.UserGroupCli = "$netbios\$gsam"; $row.UserGroup = "$gsam $chosenN/$($rusers.Count)"
                                $covered=@($gMembers[$chosen]); $row.UserGrpMissing = (@($rusers | Where-Object { (Sam-From-User $_) -notin $covered }) -join ';')
                            }
                        } elseif ($tooBig) { $row.UserGroup = "grp >2x members - suggest new" }
                    }
                    if ($done % 8 -eq 0) { UI { $txtStatus.Text = "Resolving user groups: $done/$($rows.Count)..."; $dgRM.Items.Refresh() } }
                }
                UI { $dgRM.Items.Refresh() }
            }
            UI {
                $txtStatus.Text = "Done - $fetched logs -> $($rows.Count) unique flows (rule '$rule', last $days d)"
                $fetchLock.Busy=$false; $fetchLock.Name=''
            }
            Log "[RuleMiner] Done: $fetched logs aggregated into $($rows.Count) flows. Top rows = candidate rules."
        } catch {
            $msg = $_.Exception.Message
            Log "[RuleMiner] Mining failed: $msg"
            UI { $txtStatus.Text = "Failed - see log"; $fetchLock.Busy=$false; $fetchLock.Name='' }
        } finally {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $prevSsl
        }
    })
    [void]$ps.BeginInvoke()
}

function New-RMCli {
    param([string]$Mode = 'individual')   # 'individual' = one rule per flow; 'merge' = one rule for all selected
    $sel = @($dgRM.SelectedItems)
    if ($sel.Count -eq 0) { Write-Log "[RuleMiner] Select one or more flow rows in the grid first."; return }
    $dg = $txtRMDG.Text.Trim()
    if ($dg -eq '') { Write-Log "[RuleMiner] Enter the device-group name (used in the set commands)."; return }
    $broad  = $cbRMRule.Text.Trim()
    $prefix = $txtRMPrefix.Text; if ($null -eq $prefix) { $prefix = 'ZT-' }
    $offerCreate  = [bool]$cbRMCreateGroups.IsChecked
    $restrictSrc  = [bool]$cbRMSrcRestrict.IsChecked
    $useKnownUser = [bool]$cbRMKnownUser.IsChecked
    # Per-session tagging/naming fields (JH naming standards)
    $rmRegion  = $txtRMRegion.Text.Trim()
    $rmLoc     = $txtRMLoc.Text.Trim()
    $rmEnv     = $txtRMEnv.Text.Trim()
    $rmService = $txtRMService.Text.Trim()
    $rmProfile = $txtRMProfile.Text.Trim(); if ($rmProfile -eq '') { $rmProfile = 'JH-Outbound-SP' }
    $unknownApps  = @('', 'unknown-tcp', 'unknown-udp', 'incomplete', 'insufficient-data', 'not-applicable')
    $protoMap = @{ '6'='tcp'; '17'='udp' }
    $today = (Get-Date).ToString('yyyy-MM-dd')
    $netbios = [string]$env:USERDOMAIN

    # Zones: prefer the broad rule's config (cached by Load Rules); fall back to observed log zones
    $cfgFrom = $null; $cfgTo = $null
    if ($broad -and $script:RMRuleInfo.ContainsKey($broad)) { $cfgFrom = @($script:RMRuleInfo[$broad].From); $cfgTo = @($script:RMRuleInfo[$broad].To) }

    function San([string]$s) { return ($s -replace '[^A-Za-z0-9._-]','-') }
    function Clip([string]$n) { if ($n.Length -gt 63) { return $n.Substring(0,63) } return $n }
    function FmtQ([object[]]$m) {   # quoted list for object/zone/group names
        $m = @($m | Where-Object { $_ }); if ($m.Count -eq 0) { return 'any' }
        if ($m.Count -eq 1) { return '"' + $m[0] + '"' }
        return '[ ' + (($m | ForEach-Object { '"' + $_ + '"' }) -join ' ') + ' ]'
    }
    function FmtRaw([object[]]$m) { # unquoted list for apps/services
        $m = @($m | Where-Object { $_ }); if ($m.Count -eq 0) { return 'any' }
        if ($m.Count -eq 1) { return $m[0] }
        return '[ ' + ($m -join ' ') + ' ]'
    }
    function DstTok([object[]]$d) { # quote object names, leave raw IPs bare
        $t = @(); foreach ($x in @($d | Where-Object { $_ })) { if ($x -match '^\d{1,3}(\.\d{1,3}){3}$') { $t += $x } else { $t += '"' + $x + '"' } }
        if ($t.Count -eq 0) { return 'any' }; if ($t.Count -eq 1) { return $t[0] }; return '[ ' + ($t -join ' ') + ' ]'
    }
    function SamN([string]$u) { $u = ([string]$u).Trim(); if ($u.Contains('\')) { $u = $u.Substring($u.IndexOf('\')+1) } elseif ($u.Contains('@')) { $u = $u.Substring(0,$u.IndexOf('@')) }; return $u }
    function TagClause([string[]]$tags) { $a=@($tags | Where-Object { $_ } | Select-Object -Unique); if ($a.Count -eq 0) { return '' }; return ' tag [ ' + (($a | ForEach-Object { '"'+$_+'"' }) -join ' ') + ' ]' }
    function EnsureTags([string[]]$tags) { foreach ($t in @($tags | Where-Object { $_ } | Select-Object -Unique)) { if (-not $madeTag.ContainsKey($t)) { $madeTag[$t]=$true; if (-not $script:RMTags.ContainsKey($t)) { $cli.Add("set shared tag ""$t""") } } } }
    function HasTags([string]$obj, [string[]]$need) { if (-not $script:RMObjTags.ContainsKey($obj)) { return $false }; $have=@(([string]$script:RMObjTags[$obj]) -split ';'); foreach ($n in @($need | Where-Object { $_ })) { if ($have -notcontains $n) { return $false } }; return $true }

    $cli   = New-Object 'System.Collections.Generic.List[string]'   # active CLI
    $tail  = New-Object 'System.Collections.Generic.List[string]'   # commented offers/suggestions appended after rules
    $svcs  = @{}; $names = @{}; $madeGroup = @{}; $madeObj = @{}; $madeTag = @{}

    # Build specs: each spec = a set of flows that become one rule
    $specs = @()
    if ($Mode -eq 'merge') { $specs = ,@($sel) } else { foreach ($r in $sel) { $specs += ,@($r) } }

    foreach ($flows in $specs) {
        $flows = @($flows)
        $dests=@(); $apps=@(); $svcPorts=@(); $ports=@(); $rawSrcs=@(); $srcObjs=@(); $srcGroups=@(); $unmatchedSrcs=@()
        $userGroups=@(); $allUsers=@(); $userMissing=@(); $zFrom=@(); $zTo=@(); $sessions=0; $zeroUserSessions=0
        foreach ($row in $flows) {
            $sessions += [int]$row.Sessions
            if ([int]$row.UserCount -eq 0) { $zeroUserSessions += [int]$row.Sessions }
            if ([string]$row.DstObject) { $dests += [string]$row.DstObject } else { $dests += [string]$row.Destination }
            $app=[string]$row.App; $proto=[string]$row.Protocol; if ($protoMap.ContainsKey($proto)) { $proto=$protoMap[$proto] }
            if ($proto -in @('tcp','udp') -and [string]$row.DPort) { $ports += "$proto/$($row.DPort)" }
            if ($unknownApps -contains $app.ToLower()) { if ($proto -in @('tcp','udp') -and [string]$row.DPort) { $svcPorts += "$proto/$($row.DPort)" } }
            else { $apps += $app }
            if ([string]$row.SrcGroup) { $srcGroups += [string]$row.SrcGroup }
            if ([string]$row.SrcObjects)   { $srcObjs       += (([string]$row.SrcObjects)   -split ';' | Where-Object { $_ }) }
            if ([string]$row.SrcUnmatched) { $unmatchedSrcs += (([string]$row.SrcUnmatched) -split ';' | Where-Object { $_ }) }
            $rawSrcs += (([string]$row.AllSources) -split ';' | Where-Object { $_ })
            if ([string]$row.UserGroupCli)   { $userGroups  += [string]$row.UserGroupCli }
            if ([string]$row.UserGrpMissing) { $userMissing += (([string]$row.UserGrpMissing) -split ';' | Where-Object { $_ }) }
            $allUsers += (([string]$row.AllUsers) -split ';' | Where-Object { $_ })
            if ([string]$row.FromZone) { $zFrom += [string]$row.FromZone }
            if ([string]$row.ToZone)   { $zTo   += [string]$row.ToZone }
        }
        $dests=@($dests|Select-Object -Unique); $apps=@($apps|Select-Object -Unique); $svcPorts=@($svcPorts|Select-Object -Unique); $ports=@($ports|Where-Object{$_}|Select-Object -Unique)
        $srcObjs=@($srcObjs|Select-Object -Unique); $rawSrcs=@($rawSrcs|Select-Object -Unique); $unmatchedSrcs=@($unmatchedSrcs|Select-Object -Unique)
        $srcGroups=@($srcGroups|Where-Object{$_}|Select-Object -Unique); $userGroups=@($userGroups|Where-Object{$_}|Select-Object -Unique)
        $allUsers=@($allUsers|Select-Object -Unique); $userMissing=@($userMissing|Select-Object -Unique)
        $zFrom=@($zFrom|Select-Object -Unique); $zTo=@($zTo|Select-Object -Unique)
        # If object matching was off (no classification), treat all raw sources as unmatched so they still inline / can form a group
        if ($srcObjs.Count -eq 0 -and $unmatchedSrcs.Count -eq 0 -and $rawSrcs.Count -gt 0) { $unmatchedSrcs = $rawSrcs }

        # ----- ports & naming (JH naming standards) -----
        $portNums  = @($ports | ForEach-Object { ($_ -split '/')[1] } | Where-Object { $_ } | Select-Object -Unique)
        $portLabel = if ($portNums.Count -eq 1) { $portNums[0] } elseif ($portNums.Count -gt 1) { 'Multi' } else { 'any' }
        $portTag   = "port$portLabel"
        $svcTag    = $rmService
        $srcGrpBase = if ($rmService) { San $rmService } else { 'SRC' }
        $srcGroup  = Clip $srcGrpBase
        $dstGroup  = Clip (San "$srcGrpBase-Destination_Port$portLabel")
        $name = Clip (San "$srcGroup-to-Outside_Port$portLabel")   # provisional - finalized below once user-group + destination are known

        # tag set for created objects (Region/Location/Env/Service + role)
        $baseTags = @(); foreach ($t in @($rmRegion,$rmLoc,$rmEnv,$svcTag)) { if ($t) { $baseTags += $t } }
        $srcTagClause = TagClause (@($baseTags) + @('Server'))
        $dstTagClause = TagClause (@($baseTags) + @('Destination', $portTag))

        # from / to (broad-rule zones preferred; else INSIDE/OUTSIDE per standard)
        $fromTxt = if ($cfgFrom -and $cfgFrom.Count) { FmtQ $cfgFrom } elseif ($zFrom.Count) { FmtQ $zFrom } else { '"INSIDE"' }
        $toTxt   = if ($cfgTo   -and $cfgTo.Count)   { FmtQ $cfgTo   } elseif ($zTo.Count)   { FmtQ $zTo   } else { '"OUTSIDE"' }

        # GP-VPN zone special case
        $gpGroup = 'Global Protect Subnets'
        $fromZonesAll = @(); if ($cfgFrom) { $fromZonesAll += $cfgFrom }; $fromZonesAll += $zFrom
        $toZonesAll   = @(); if ($cfgTo)   { $toZonesAll   += $cfgTo   }; $toZonesAll   += $zTo
        $isGpFrom = [bool](@($fromZonesAll) | Where-Object { $_ -like '*GP-VPN*' })
        $isGpTo   = [bool](@($toZonesAll)   | Where-Object { $_ -like '*GP-VPN*' })

        # ----- SOURCE address (dynamic tag-based group when Service set) -----
        if ($isGpFrom) {
            $srcTxt = '"' + $gpGroup + '"'
        } elseif ($rmService) {
            if ($offerCreate) {
                EnsureTags (@($baseTags) + @('Server'))
                if (-not $madeGroup.ContainsKey($srcGroup)) { $madeGroup[$srcGroup]=$true; if (-not $script:RMGroups.ContainsKey($srcGroup)) { $cli.Add("set shared address-group ""$srcGroup"" dynamic filter ""'$svcTag' and 'Server'""") } }
                foreach ($o in $srcObjs)        { if (-not (HasTags $o (@($baseTags)+@('Server')))) { $cli.Add("set shared address ""$o""$srcTagClause") } }
                foreach ($ip in $unmatchedSrcs) { $oN = Clip (San "$srcGrpBase-$ip"); if (-not $madeObj.ContainsKey($oN)) { $madeObj[$oN]=$true; $cli.Add("set shared address ""$oN"" ip-netmask $ip/32$srcTagClause") } }
            }
            $srcTxt = '"' + $srcGroup + '"'
        } elseif ($restrictSrc -and ($srcObjs.Count -or $unmatchedSrcs.Count)) {
            $toks = @($srcObjs | ForEach-Object { '"'+$_+'"' }) + @($unmatchedSrcs)
            if ($toks.Count -le 20) { $srcTxt = '[ ' + ($toks -join ' ') + ' ]' } else { $srcTxt='any'; Write-Log "[RuleMiner] '$name': >20 sources, no Service set - source any. Set the Service field to build a dynamic group." }
        } else {
            $srcTxt = if ($unmatchedSrcs.Count -eq 0 -and $srcGroups.Count -ge 1) { FmtQ $srcGroups } else { 'any' }
        }

        # ----- DESTINATION address (dynamic tag-based group when Service set) -----
        if ($isGpTo) {
            $dstTxt = '"' + $gpGroup + '"'
        } elseif ($rmService) {
            if ($offerCreate) {
                EnsureTags (@($baseTags) + @('Destination', $portTag))
                if (-not $madeGroup.ContainsKey($dstGroup)) { $madeGroup[$dstGroup]=$true; if (-not $script:RMGroups.ContainsKey($dstGroup)) { $cli.Add("set shared address-group ""$dstGroup"" dynamic filter ""'$svcTag' and 'Destination' and '$portTag'""") } }
                foreach ($d in $dests) {
                    if ($d -match '^\d{1,3}(\.\d{1,3}){3}$') { $oN = Clip (San "$srcGrpBase-Dest-$d"); if (-not $madeObj.ContainsKey($oN)) { $madeObj[$oN]=$true; $cli.Add("set shared address ""$oN"" ip-netmask $d/32$dstTagClause") } }
                    elseif (-not (HasTags $d (@($baseTags)+@('Destination',$portTag)))) { $cli.Add("set shared address ""$d""$dstTagClause") }
                }
            }
            $dstTxt = '"' + $dstGroup + '"'
        } else {
            $dstTxt = DstTok $dests
            if (-not $rmService -and -not $isGpTo) { Write-Log "[RuleMiner] '$name': Service field is empty - using raw object refs, no tags or dynamic group created. Set the Service field to generate tagged objects + a dynamic group per the naming standard." }
        }

        # ----- application + service (service objects <proto>-<port>, shared) -----
        $svcObjs=@()
        foreach ($pp in $ports) {
            $aa=$pp -split '/'; $pProto=$aa[0]; $pNum=$aa[1]
            if ($script:RMSvc.ContainsKey("$pProto/$pNum")) { $svcObjs += [string]$script:RMSvc["$pProto/$pNum"] }   # reuse existing service
            else { $sn="$pProto-$pNum"; if (-not $svcs.ContainsKey($sn)) { $svcs[$sn]=$true; $cli.Add("set shared service ""$sn"" protocol $pProto port $pNum") }; $svcObjs+=$sn }
        }
        $svcObjs=@($svcObjs|Select-Object -Unique)
        $appTxt = if ($apps.Count) { FmtRaw $apps } else { 'any' }
        $svcTxt = if ($svcObjs.Count) { FmtRaw $svcObjs } else { 'application-default' }

        # source-user
        $userTxt=''
        if ($userGroups.Count -ge 1) {
            $userTxt = ' source-user ' + (FmtQ $userGroups)
            if ($userMissing.Count) { Write-Log "[RuleMiner] '$name': used group(s); $($userMissing.Count) observed user(s) NOT in group - add them or keep known-user: $($userMissing -join ', ')" }
        } else {
            if ($useKnownUser) {
                $userTxt = ' source-user known-user'
                if ($zeroUserSessions -gt 0) { Write-Log "[RuleMiner] WARNING '$name': $zeroUserSessions session(s) had 0 mapped users (machine traffic). known-user WILL BLOCK these - consider unchecking known-user." }
            }
            if ($offerCreate -and $allUsers.Count -gt 0 -and $allUsers.Count -lt 200) {
                $ugName = Clip (San ($name + '-users'))
                $sams = @($allUsers | ForEach-Object { "'" + (SamN $_) + "'" }) | Select-Object -Unique
                $tail.Add("# ---- No AD group matched (or best group >2x the users) for these $($allUsers.Count) user(s). Suggested NEW group (run in PowerShell with the AD module / RSAT): ----")
                $tail.Add("#   New-ADGroup -Name '$ugName' -GroupScope Global -Path 'OU=Groups,DC=CHANGE,DC=ME'")
                $tail.Add("#   Add-ADGroupMember -Identity '$ugName' -Members " + ($sams -join ','))
                $tail.Add("#   Then add '$ugName' to Panorama group-mapping include-list, and set the rule's source-user to ""$netbios\$ugName"".")
            }
        }

        # Final rule name: when a user group is the source identity, name it <USER-GROUP>-to-<SERVER-GROUP/NAME>
        $destLabel = if ($isGpTo) { $gpGroup } elseif ($rmService) { $dstGroup } elseif ($dests.Count -eq 1) { $dests[0] } else { 'Outside' }
        if ($userGroups.Count -ge 1) {
            $ugShort = [string]$userGroups[0]; if ($ugShort.Contains('\')) { $ugShort = $ugShort.Substring($ugShort.IndexOf('\')+1) }
            $name = "$ugShort-to-$destLabel"
        } else {
            $name = "$srcGroup-to-Outside_Port$portLabel"
        }
        $name = Clip (San $name)
        if ($names.ContainsKey($name)) { $names[$name]++; $sfx='-'+$names[$name]; $name = (Clip ($name.Substring(0,[Math]::Min($name.Length,63-$sfx.Length)))) + $sfx } else { $names[$name]=1 }

        $desc = "Mined from '$broad' ${today}: $sessions sessions ($($flows.Count) flow(s))"
        # NOTE: description must precede profile-setting in the set command - Panorama rejects the reverse order.
        $cli.Add("set device-group $dg pre-rulebase security rules ""$name"" from $fromTxt to $toTxt source $srcTxt$userTxt destination $dstTxt application $appTxt service $svcTxt action allow log-end yes description ""$desc"" profile-setting group ""$rmProfile""")
        if ($broad) { $cli.Add("move device-group $dg pre-rulebase security rules ""$name"" before ""$broad""") }
    }

    foreach ($t in $tail) { $cli.Add($t) }
    $txtRMCli.Text = ($cli -join "`r`n")
    Write-Log "[RuleMiner] [$Mode] Generated $($cli.Count) line(s) for $($sel.Count) selected flow(s). Review, copy, paste into Panorama (configure mode), then commit + push."
}

$btnRMLoadRules.Add_Click({ Invoke-RMLoadRules })
$btnRMFetch.Add_Click({     Invoke-RMFetch })
$btnRMGenCli.Add_Click({    New-RMCli -Mode 'individual' })
$btnRMGenMerge.Add_Click({  New-RMCli -Mode 'merge' })
$btnRMCopyCli.Add_Click({
    if ($txtRMCli.Text.Trim() -ne '') {
        [System.Windows.Clipboard]::SetText($txtRMCli.Text)
        Write-Log "[RuleMiner] CLI copied to clipboard."
    } else { Write-Log "[RuleMiner] Nothing to copy - generate CLI first." }
})
$btnExportRM.Add_Click({ Export-CollToCSV $script:ColRM 'ruleminer' })

# ── Shutdown ─────────────────────────────────────────────────
$Window.Add_Closing({
    $script:PingCtrl.Stop       = $true
    $script:RebootPollCtrl.Stop = $true
})

Write-Log "Palo Alto Firewall Manager ready. Enter Panorama IP and click Connect."
# Queue drainer: when the lock is free and actions are queued, run the next one (UI thread).
$script:QueueTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:QueueTimer.Interval = [TimeSpan]::FromMilliseconds(500)
$script:QueueTimer.Add_Tick({
    try {
        if ((-not $script:FetchLock.Busy) -and $script:ActionQueue.Count -gt 0) {
            $item = $script:ActionQueue.Dequeue()
            Write-Log "[Queue] Starting '$($item.Label)' ($($script:ActionQueue.Count) still queued)..."
            if ($item.Button) { $item.Button.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)) }
        }
    } catch { try { Write-Log "[Queue] tick error: $($_.Exception.Message)" } catch { } }
})
$script:QueueTimer.Start()

# Capture the last-clicked button (used by Begin-Fetch to queue actions while busy).
# FULLY guarded: an exception escaping a WPF input/handler poisons the whole PowerShell session.
$Window.AddHandler(
    [System.Windows.UIElement]::PreviewMouseLeftButtonDownEvent,
    [System.Windows.Input.MouseButtonEventHandler]{
        param($s,$e)
        try {
            $el = $e.OriginalSource
            while ($el -and -not ($el -is [System.Windows.Controls.Primitives.ButtonBase])) {
                if ($el -isnot [System.Windows.DependencyObject]) { $el = $null; break }   # ContentElement etc. -> GetParent would throw
                $el = [System.Windows.Media.VisualTreeHelper]::GetParent($el)
            }
            if ($el) { $script:LastClicked = $el }
        } catch { }
    },
    $true)

# Action bar (HA / SW / Cfg / Reboot) only on the Devices tab. Null-guarded + try/catch so it can never poison the dispatcher.
function Set-ActionBarVisibility {
    try {
        if ($brdActionBar) {
            if ($tabMain.SelectedItem -and ([string]$tabMain.SelectedItem.Header) -like '*Devices*') { $brdActionBar.Visibility = 'Visible' } else { $brdActionBar.Visibility = 'Collapsed' }
        }
    } catch { }
}
$tabMain.Add_SelectionChanged({ Set-ActionBarVisibility })
Set-ActionBarVisibility   # initial state (default Devices tab)

[void]$Window.ShowDialog()
