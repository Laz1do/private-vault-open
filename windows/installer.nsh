!macro customUnInstall
  SetRegView 32
  DeleteRegKey HKCU "Software\Google\Chrome\NativeMessagingHosts\com.local.privatevault"
  SetRegView 64
  DeleteRegKey HKCU "Software\Google\Chrome\NativeMessagingHosts\com.local.privatevault"
!macroend
