# TrickMo APK extraction profile

This is the concrete extraction view of the TrickMo research catalog. It tells an APK analyzer what to collect and which relationships to verify. It does not treat every listed Android capability as a TrickMo signature.

The machine-readable version is [extraction-profile.json](extraction-profile.json). The relationship requirements are in [verification-templates.json](verification-templates.json).

## Evidence labels

| Label | Meaning |
|---|---|
| `reported_exact_token` | The reviewed source contains this literal token. |
| `reported_behavior` | Researchers report the behavior, but the exact implementing token is not established. |
| `behavior_derived_search_target` | Useful Android API or manifest lead for verifying the behavior; not a TrickMo IOC. |
| `unverified_candidate` | Proposed lead that still needs a source or sample confirmation. |

## 1. Manifest and component extraction

Extract all manifest permissions, services, receivers, activities, intent filters, metadata, exported flags, and foreground-service types. Preserve the declaration location.

| Artifact | How to store it | Evidence label | Behavior seed |
|---|---|---|---|
| `android.permission.BIND_ACCESSIBILITY_SERVICE` | `component_binding_permission` on a service, with the accessibility-service intent and metadata | behavior-derived | Accessibility automation |
| `SYSTEM_ALERT_WINDOW` | uses-permission | behavior-derived | Overlay investigation |
| `RECEIVE_SMS`, `READ_SMS`, `SEND_SMS` | separate uses-permissions | behavior-derived | SMS investigation |
| `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` | uses-permission | unverified candidate | None until sourced |
| `READ_CALL_LOG`, `READ_CONTACTS`, `WRITE_EXTERNAL_STORAGE` | separate uses-permissions | unverified candidates | None until sourced |
| `SMS_DELIVER`, `SCREEN_ON` | retain as reported short intent names | reported exact tokens | SMS/event investigation |
| `BOOT_COMPLETED`, `SMS_RECEIVED` | exact manifest/dynamic registration if present | unverified candidates | Generic persistence/SMS leads |

`BIND_ACCESSIBILITY_SERVICE` is not an ordinary requested permission in this profile. Android declares it on the accessibility service so only the system can bind to that component. Its presence proves a declared service capability, not user enablement or abuse.

## 2. API and method extraction

The following are graph seeds. Store the fully qualified owner, method, descriptor, caller, file/line, arguments, return-use sites, and containing component.

| API or method | Verification target |
|---|---|
| `AccessibilityService.dispatchGesture()` | Configuration/event/command controls a concrete gesture or UI action. |
| `AccessibilityNodeInfo.getText()` | Returned UI text reaches targeting, storage, or a network sink. |
| `findAccessibilityNodeInfosByText()` | Search results control a resolved accessibility action. |
| `MediaProjectionManager.createScreenCaptureIntent()` | Consent result reaches capture setup; captured data reaches a file, socket, or request. |
| `WindowManager.addView()` | Added view contains deceptive input and is selected by target-app or unlock context. |
| `SmsManager.getDefault()` | Follow actual downstream SMS operations; this call only obtains a manager for the default subscription. |
| `DexClassLoader.loadClass()` | An embedded/downloaded payload is recovered and passed to the loader. |
| `PackageManager.setComponentEnabledSetting()` | Resolve the component and requested state before describing icon hiding. |

These exact APIs were not all published as TrickMo sample signatures in the reviewed reports. They operationalize reported behaviors for the analyzer.

## 3. Exact strings, commands, and paths

Source-confirmed tokens in this collection:

- `SaveHtml` — reported C2 command and overlay seed.
- `getAndroidID` — reported exposed method name in the unlock-page flow.
- `clicker.json` — reported accessibility automation configuration asset.
- `assets/base.apk`, `dreammes.ross431.in`, `com.turkey.inner.Uactortrust`, and `/data/user/0/dreammes.ross431.in/app_inflict/wF.json` — reported cohort-specific unpacking artifacts.
- `JSONPacker` — reported packer marker.

Keep `get_inject`, `update_sms`, `upload_photo`, `start_screen_record`, `Google Services`, and `Google Play Services update` as unverified candidates until a cited report or a hashed local sample establishes them. A `.php` suffix is only a very low-specificity network-search lead. It becomes useful when a resolved user-input or collected-data flow reaches that request.

## 4. Structural extraction

Record ZIP central-directory and local-header inconsistencies, duplicate/invalid entries, parser failures, embedded APK/DEX assets, JSON-based payload material, decode/decrypt routines, written executable files, and loader calls. Hash every recovered stage and keep its call graph separate until a verified loading edge links it to another stage.

Malformed ZIP structure and JSON-based packing are reported TrickMo-cohort behaviors. Neither proves family identity alone. A complete packed-payload finding requires:

```text
embedded/downloaded payload
        -> decode, decrypt, or unpack
        -> executable code loader
```

## 5. Collective behavior bundles

The matcher should use individual artifacts to start investigation and use APK-local edges to confirm behavior:

```text
Accessibility automation:
service declaration + configuration -> callback -> UI action

Credential overlay:
target context -> deceptive UI -> user input -> network request

SMS interception:
SMS event -> message content -> storage/suppression/transmission

Screen collection:
target or command context -> capture source -> file/socket/request

Packed payload:
payload source -> recovery transform -> runtime loader
```

Only resolved nodes and edges from the analyzed APK become APK evidence. Research records remain external context. Several supported behavior bundles may justify a conservative family-similarity assessment, but they do not by themselves prove that the APK is TrickMo.
