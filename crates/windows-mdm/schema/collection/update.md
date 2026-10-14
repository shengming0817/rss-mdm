---
layout: Conceptual
title: Update CSP | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows/client-management/mdm/update-csp
recommendations: true
adobe-target: true
ms.collection:
- tier2
breadcrumb_path: /windows/resources/breadcrumb/toc.json
uhfHeaderId: MSDocsHeader-Windows
audience: ITPro
ms.service: windows-client
ms.subservice: itpro-manage
ms.topic: reference
ms.author: odocspr
author: officedocspr5
manager: bpardi
feedback_system: Standard
feedback_product_url: https://support.microsoft.com/windows/send-feedback-to-microsoft-with-the-feedback-hub-app-f59187f8-8739-22d6-ba93-f66612949332
description: Learn how the Update configuration service provider (CSP) enables IT administrators to manage and control the rollout of new updates.
ms.date: 2023-11-16T00:00:00.0000000Z
locale: en-us
document_id: 85da8b6b-3138-1fe8-15b6-e3ab96c12efb
document_version_independent_id: 236d9dbb-f05e-b3fd-ee43-c2081b4f4300
updated_at: 2024-01-18T23:52:00.0000000Z
original_content_git_url: https://github.com/MicrosoftDocs/windows-docs-pr/blob/live/windows/client-management/mdm/update-csp.md
gitcommit: https://github.com/MicrosoftDocs/windows-docs-pr/blob/e0d0d9d49f69115a321161f97d084bbfb7faefd7/windows/client-management/mdm/update-csp.md
git_commit_id: e0d0d9d49f69115a321161f97d084bbfb7faefd7
site_name: Docs
depot_name: TechNet.win-client-management
page_type: conceptual
toc_rel: toc.json
pdf_url_template: https://learn.microsoft.com/pdfstore/en-us/TechNet.win-client-management/{branchName}{pdfName}
feedback_help_link_type: ''
feedback_help_link_url: ''
word_count: 1111
asset_id: mdm/update-csp
moniker_range_name: 
monikers: []
item_type: Content
source_path: windows/client-management/mdm/update-csp.md
cmProducts:
- https://authoring-docs-microsoft.poolparty.biz/devrel/bcbcbad5-4208-4783-8035-8481272c98b8
- https://authoring-docs-microsoft.poolparty.biz/devrel/e0ffb20c-01c6-407b-a9bd-29111652a1dc
spProducts:
- https://authoring-docs-microsoft.poolparty.biz/devrel/43b2e5aa-8a6d-4de2-a252-692232e5edc8
- https://authoring-docs-microsoft.poolparty.biz/devrel/3904bce4-d817-48cf-85fd-b6146fca83b7
platformId: 0d0fa4dc-7cbe-18e0-aedf-7ae08a077ea9
---

# Update CSP | Microsoft Learn

The Update configuration service provider enables the IT administrators to manage and control the rollout of new updates.

The table below shows the applicability of Windows:

| Edition | Windows 10 | Windows 11 |
| --- | --- | --- |
| Home | Yes | Yes |
| Pro | Yes | Yes |
| Windows SE | No | Yes |
| Business | Yes | Yes |
| Enterprise | Yes | Yes |
| Education | Yes | Yes |

Note

The Update CSP functionality of 'ApprovedUpdates' is not recommended for managing desktop devices. To manage updates to desktop devices from Windows Update, see the [Policy CSP - Updates](policy-csp-update) documentation for the recommended policies.

The following example shows the Update configuration service provider in tree format.

```
./Vendor/MSFT/Update
----ApprovedUpdates
--------Approved Update Guid
------------ApprovedTime
----FailedUpdates
--------Failed Update Guid
------------HResult
------------State
------------RevisionNumber
----InstalledUpdates
--------Installed Update Guid
------------RevisionNumber
----InstallableUpdates
--------Installable Update Guid
------------Type
------------RevisionNumber
----PendingRebootUpdates
--------Pending Reboot Update Guid
------------InstalledTime
------------RevisionNumber
----LastSuccessfulScanTime
----DeferUpgrade
----Rollback
--------QualityUpdate
--------FeatureUpdate
--------QualityUpdateStatus
--------FeatureUpdateStatus
```

**./Vendor/MSFT/Update** The root node.

Supported operation is Get.

**ApprovedUpdates** Node for update approvals and EULA acceptance on behalf of the end-user.

Note

When the RequireUpdateApproval policy is set, the MDM uses the ApprovedUpdates list to pass the approved GUIDs. These GUIDs should be a subset of the InstallableUpdates list.

The MDM must first present the EULA to IT and have them accept it before the update is approved. Failure to do this is a breach of legal or contractual obligations. The EULAs can be obtained from the update metadata and have their own EULA ID. It's possible for multiple updates to share the same EULA. It is only necessary to approve the EULA once per EULA ID, not one per update.

The update approval list enables IT to approve individual updates and update classifications. Auto-approval by update classifications allows IT to automatically approve Definition Updates (that is, updates to the virus and spyware definitions on devices) and Security Updates (that is, product-specific updates for security-related vulnerability). The update approval list doesn't support the uninstallation of updates by revoking approval of already installed updates. Updates are approved based on UpdateID, and an UpdateID only needs to be approved once. An update UpdateID and RevisionNumber are part of the UpdateIdentity type. An UpdateID can be associated to several UpdateIdentity GUIDs due to changes to the RevisionNumber setting. MDM services must synchronize the UpdateIdentity of an UpdateID based on the latest RevisionNumber to get the latest metadata for an update. However, update approval is based on UpdateID.

Note

For the Windows 10 build, the client may need to reboot after additional updates are added.

Supported operations are Get and Add.

**ApprovedUpdates/*Approved Update Guid*** Specifies the update GUID.

To auto-approve a class of updates, you can specify the [Update Classifications](/en-us/previous-versions/windows/desktop/ff357803%28v=vs.85%29) GUIDs. We strongly recommend to always specify the DefinitionsUpdates classification (E0789628-CE08-4437-BE74-2495B842F43B), which are used for anti-malware signatures. These GUIDs are released periodically (several times a day). Some businesses may also want to auto-approve security updates to get them deployed quickly.

Supported operations are Get and Add.

Sample syncml:

```
<LocURI>./Vendor/MSFT/Update/ApprovedUpdates/%7ba317dafe-baf4-453f-b232-a7075efae36e%7d</LocURI>
```

**ApprovedUpdates/*Approved Update Guid*/ApprovedTime** Specifies the time the update gets approved.

Supported operations are Get and Add.

**FailedUpdates** Specifies the approved updates that failed to install on a device.

Supported operation is Get.

**FailedUpdates/*Failed Update Guid*** Update identifier field of the UpdateIdentity GUID that represents an update that failed to download or install.

Supported operation is Get.

**FailedUpdates/*Failed Update Guid*/HResult** The update failure error code.

Supported operation is Get.

**FailedUpdates/*Failed Update Guid*/State** Specifies the failed update state.

| Update Status | Integer Value |
| --- | --- |
| UpdateStatusNewUpdate | 1 |
| UpdateStatusReadyToDownload | 2 |
| UpdateStatusDownloading | 4 |
| UpdateStatusDownloadBlocked | 8 |
| UpdateStatusDownloadFailed | 16 |
| UpdateStatusReadyToInstall | 32 |
| UpdateStatusInstalling | 64 |
| UpdateStatusInstallBlocked | 128 |
| UpdateStatusInstallFailed | 256 |
| UpdateStatusRebootRequired | 512 |
| UpdateStatusUpdateCompleted | 1024 |
| UpdateStatusCommitFailed | 2048 |
| UpdateStatusPostReboot | 4096 |

Supported operation is Get.

**FailedUpdates/*Failed Update Guid*/RevisionNumber** Added in Windows 10, version 1703. The revision number for the update that must be passed in server to server sync to get the metadata for the update.

Supported operation is Get.

**InstalledUpdates** The updates that are installed on the device.

Supported operation is Get.

**InstalledUpdates/*Installed Update Guid*** UpdateIDs that represent the updates installed on a device.

Supported operation is Get.

**InstalledUpdates/*Installed Update Guid*/RevisionNumber** Added in Windows 10, version 1703. The revision number for the update that must be passed in server to server sync to get the metadata for the update.

Supported operation is Get.

**InstallableUpdates** The updates that are applicable and not yet installed on the device. These updates include updates that aren't yet approved.

Supported operation is Get.

**InstallableUpdates/*Installable Update Guid*** Update identifiers that represent the updates applicable and not installed on a device.

Supported operation is Get.

**InstallableUpdates/*Installable Update Guid*/Type** The UpdateClassification value of the update. Valid values are:

- 0 - None
- 1 - Security
- 2 - Critical

Supported operation is Get.

**InstallableUpdates/*Installable Update Guid*/RevisionNumber** The revision number for the update that must be passed in server to server sync to get the metadata for the update.

Supported operation is Get.

**PendingRebootUpdates** The updates that require a reboot to complete the update session.

Supported operation is Get.

**PendingRebootUpdates/*Pending Reboot Update Guid*** Update identifiers for the pending reboot state.

Supported operation is Get.

**PendingRebootUpdates/*Pending Reboot Update Guid*/InstalledTime** The time the update is installed.

Supported operation is Get.

**PendingRebootUpdates/*Pending Reboot Update Guid*/RevisionNumber** Added in Windows 10, version 1703. The revision number for the update that must be passed in server to server sync to get the metadata for the update.

Supported operation is Get.

**LastSuccessfulScanTime** The last successful scan time.

Supported operation is Get.

**DeferUpgrade** Upgrades deferred until the next period.

Supported operation is Get.

**Rollback** Added in Windows 10, version 1803. Node for the rollback operations.

**Rollback/QualityUpdate** Added in Windows 10, version 1803. Roll back latest Quality Update, if the machine meets the following conditions:

- Condition 1: Device must be Windows Update for Business Connected
- Condition 2: Device must be in a Paused State
- Condition 3: Device must have the Latest Quality Update installed on the device (Current State)

If the conditions aren't true, the device won't Roll Back the Latest Quality Update.

**Rollback/FeatureUpdate** Added in Windows 10, version 1803. Roll Back Latest Feature Update, if the machine meets the following conditions:

- Condition 1: Device must be Windows Update for Business Connected
- Condition 2: Device must be in Paused State
- Condition 3: Device must have the Latest Feature Update Installed on the device (Current State)
- Condition 4: Machine should be within the uninstall period

Note

This only works for General Availability Channel Targeted devices.

If the conditions aren't true, the device won't Roll Back the Latest Feature Update.

**Rollback/QualityUpdateStatus** Added in Windows 10, version 1803. Returns the result of last RollBack QualityUpdate operation.

**Rollback/FeatureUpdateStatus** Added in Windows 10, version 1803. Returns the result of last RollBack FeatureUpdate operation.