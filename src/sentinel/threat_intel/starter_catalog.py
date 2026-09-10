"""Versioned analyst-authored behavior templates, not family signatures.

API terminal names are initial search signals. Types and relationships must be
verified in APK source. Reference links are API documentation, not malware proof.
"""
from sentinel.threat_intel.models import ThreatKnowledge, BehaviorRelationship
from sentinel.rag.models import KnowledgeDocument


# id, name, APIs, permissions, source, sink, false-positive context
ROWS = [
 ('ACCESS','Accessibility abuse','getRootInActiveWindow performGlobalAction dispatchGesture findAccessibilityNodeInfosByText','BIND_ACCESSIBILITY_SERVICE','Accessibility callback','UI action','Assistive technology'),
 ('SMS','SMS interception','createFromPdu getMessageBody getOriginatingAddress','READ_SMS RECEIVE_SMS','SMS event','message storage or transmission','Default SMS clients'),
 ('NOTIFICATION','Notification interception','onNotificationPosted getActiveNotifications','BIND_NOTIFICATION_LISTENER_SERVICE','notification callback','notification content collection','Notification management apps'),
 ('OVERLAY','Overlay/phishing investigation','addView','SYSTEM_ALERT_WINDOW','target application context','credential collection','Floating widgets'),
 ('CREDENTIAL','Credential collection','getText getPassword','','credential input','storage or transmission','Normal authentication screens'),
 ('CLIPBOARD','Clipboard collection','getPrimaryClip hasPrimaryClip','','clipboard','storage or transmission','Clipboard managers'),
 ('SCREEN','Screen capture / MediaProjection','createScreenCaptureIntent getMediaProjection createVirtualDisplay','','screen capture consent','recorded screen content','Screen-sharing applications'),
 ('UI','Keylogging / UI collection','onAccessibilityEvent getText','BIND_ACCESSIBILITY_SERVICE','Accessibility UI event','collected text','Accessibility assistance'),
 ('CONTACTS','Contacts collection','query','READ_CONTACTS','Contacts provider','collection or transmission','Address-book apps'),
 ('CALLLOG','Call log collection','query','READ_CALL_LOG','CallLog provider','collection or transmission','Dialer applications'),
 ('LOCATION','Location collection','getLastKnownLocation requestLocationUpdates','ACCESS_FINE_LOCATION ACCESS_COARSE_LOCATION','location update','storage or transmission','Navigation'),
 ('MIC','Microphone recording','startRecording','RECORD_AUDIO','microphone','recorded audio','Voice recording'),
 ('CAMERA','Camera capture','openCamera takePicture','CAMERA','camera','captured media','Camera apps'),
 ('FILES','File/data collection','openInputStream listFiles','READ_EXTERNAL_STORAGE','file read','storage or transmission','Backup utilities'),
 ('PACKAGES','Installed-app enumeration','getInstalledPackages getInstalledApplications','QUERY_ALL_PACKAGES','package manager','application inventory','Device administration'),
 ('RECON','Device/system reconnaissance','getDeviceId getSystemService','READ_PHONE_STATE','device identifier/system service','inventory or transmission','Diagnostics'),
 ('PROCESS','Process and Command Execution','exec start','','user input or command configuration','Runtime.exec / ProcessBuilder','Diagnostics and developer tools'),
 ('DYNAMIC','Dynamic Code Loading','loadClass DexClassLoader PathClassLoader','','local/downloaded code','class loading and invocation','Plugin architectures'),
 ('NATIVE','Native library loading','loadLibrary load','','native library path','native loader','JNI libraries'),
 ('PERSIST','Boot Persistence','startService startForegroundService','RECEIVE_BOOT_COMPLETED','BOOT_COMPLETED receiver','service start','Alarm and synchronization apps'),
 ('FOREGROUND','Foreground-service persistence','startForeground startForegroundService','FOREGROUND_SERVICE','service start','ongoing service','Media playback'),
 ('JOBS','Scheduled-job persistence','schedule enqueue','','scheduled job','job execution callback','Background synchronization'),
 ('RECEIVER','Runtime receiver registration','registerReceiver','','receiver registration','event callback','Normal lifecycle handling'),
 ('ANTIANALYSIS','Anti-analysis / emulator checks','isDebuggerConnected waitingForDebugger','','environment check','conditional behavior','Debugging and compatibility checks'),
 ('ROOT','Root detection / privilege checks','exec canExecute','','privilege check','conditional behavior','Integrity checks'),
 ('HIDING','Package / launcher hiding','setComponentEnabledSetting','','launcher component','component state change','Launcher aliases'),
 ('ADMIN','Device-admin abuse investigation','lockNow wipeData resetPassword','BIND_DEVICE_ADMIN','device-admin authorization','device policy operation','Enterprise administration'),
 ('NETWORK','Network / C2 investigation','openConnection connect newCall','INTERNET','command input/network response','request handler','Normal client/server apps'),
 ('EXFIL','Data exfiltration investigation','openConnection getOutputStream','INTERNET','sensitive data source','network output','User-authorized sync'),
 ('CRYPTO','Encryption / crypto usage','getInstance doFinal init','','plaintext/key material','cryptographic operation','Data protection'),
 ('REFLECTION','Reflection','getDeclaredMethod getMethod invoke','','class/method lookup','reflection invocation','Framework compatibility'),
 ('WEBSOCKET','WebSocket / long-lived communication','newWebSocket send','INTERNET','socket event','message handler','Messaging applications'),
 ('DEX','DEX / JAR loading','DexClassLoader loadClass','','DEX/JAR bytes','class instantiation/invocation','Plugin systems'),
 ('INSTALL','Package installation/update investigation','createSession commit installPackage','REQUEST_INSTALL_PACKAGES','package payload','package installer','App stores'),
 ('AUTOMATION','Accessibility-driven UI automation','dispatchGesture performGlobalAction performAction','BIND_ACCESSIBILITY_SERVICE','Accessibility callback','resolved UI action','Assistive automation'),
]

INTENTS = {'PERSIST':['android.intent.action.BOOT_COMPLETED'],
           'SMS':['android.provider.Telephony.SMS_RECEIVED','android.provider.Telephony.SMS_DELIVER']}


def starter_records():
    result = []
    for key,name,apis,permissions,source,sink,false_positive in ROWS:
        result.append(ThreatKnowledge(knowledge_id=f'THREAT-{key}-001',name=name,
            description=f'Investigate whether {source} is connected to {sink}. Individual indicators are not proof of malicious behavior.',
            malware_behavior_category=key,apis=apis.split(),
            permissions=['android.permission.'+p for p in permissions.split()],
            sources=[source],sinks=[sink],intents=INTENTS.get(key,[]),
            behaviors=[BehaviorRelationship(source=source,operation='source-backed relationship required',sink=sink)],
            behavior_sequences=[[source,'resolved local implementation',sink]],
            associated_capabilities=[key.lower()],known_false_positives=[false_positive],
            references=['https://developer.android.com/reference'],
            source='SentinelRAG local analyst-authored starter catalog'))
    return result


def catalog_documents(records):
    return [KnowledgeDocument(document_id=r.knowledge_id,title=r.name,
        content=r.description+'\nExpected investigation sequence (not APK evidence): '+
            '; '.join(' -> '.join(s) for s in r.behavior_sequences)+
            '\nBenign explanations: '+', '.join(r.known_false_positives),
        source=r.source,metadata={'scope':'KNOWLEDGE','version':r.schema_version}) for r in records]


def merge_catalog(records):
    """Preserve legacy indicators while adding typed template metadata."""
    catalog = {r.knowledge_id:r for r in starter_records()}
    for record in records:
        if record.knowledge_id in catalog:
            template = catalog[record.knowledge_id]
            record = ThreatKnowledge.model_validate({**template.model_dump(),**record.model_dump(),
                'behavior_sequences':template.behavior_sequences,
                'known_false_positives':template.known_false_positives,
                'sources':template.sources,'sinks':template.sinks,'intents':template.intents,
                'malware_behavior_category':template.malware_behavior_category})
        catalog[record.knowledge_id] = record
    return list(catalog.values())
