---
layout: Conceptual
title: Win32AppInventory CSP | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/windows/client-management/mdm/win32appinventory-csp
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
description: Learn how the Win32AppInventory configuration service provider (CSP) is used to provide an inventory of installed applications on a device.
ms.date: 2017-06-26T00:00:00.0000000Z
locale: en-us
document_id: 614d2af1-0dc5-71eb-bbc3-85c1a3077727
document_version_independent_id: fb9c5dae-3aae-2b1f-417d-9ea2cf066f0c
updated_at: 2024-01-18T23:52:00.0000000Z
original_content_git_url: https://github.com/MicrosoftDocs/windows-docs-pr/blob/live/windows/client-management/mdm/win32appinventory-csp.md
gitcommit: https://github.com/MicrosoftDocs/windows-docs-pr/blob/e0d0d9d49f69115a321161f97d084bbfb7faefd7/windows/client-management/mdm/win32appinventory-csp.md
git_commit_id: e0d0d9d49f69115a321161f97d084bbfb7faefd7
site_name: Docs
depot_name: TechNet.win-client-management
page_type: conceptual
toc_rel: toc.json
pdf_url_template: https://learn.microsoft.com/pdfstore/en-us/TechNet.win-client-management/{branchName}{pdfName}
feedback_help_link_type: ''
feedback_help_link_url: ''
word_count: 308
asset_id: mdm/win32appinventory-csp
moniker_range_name: 
monikers: []
item_type: Content
source_path: windows/client-management/mdm/win32appinventory-csp.md
cmProducts:
- https://authoring-docs-microsoft.poolparty.biz/devrel/bcbcbad5-4208-4783-8035-8481272c98b8
- https://authoring-docs-microsoft.poolparty.biz/devrel/e0ffb20c-01c6-407b-a9bd-29111652a1dc
- https://microsoft-devrel.poolparty.biz/DevRelOfferingOntology/19ec6774-09b8-473e-a17e-b17b518bbad7
spProducts:
- https://authoring-docs-microsoft.poolparty.biz/devrel/43b2e5aa-8a6d-4de2-a252-692232e5edc8
- https://authoring-docs-microsoft.poolparty.biz/devrel/3904bce4-d817-48cf-85fd-b6146fca83b7
- https://microsoft-devrel.poolparty.biz/DevRelOfferingOntology/ade36b61-c646-4bd8-87ee-f3a843461962
platformId: a711ae91-d0d1-092c-97f4-6462de4d861d
---

# Win32AppInventory CSP | Microsoft Learn

The table below shows the applicability of Windows:

| Edition | Windows 10 | Windows 11 |
| --- | --- | --- |
| Home | No | No |
| Pro | Yes | Yes |
| Windows SE | No | Yes |
| Business | Yes | Yes |
| Enterprise | Yes | Yes |
| Education | Yes | Yes |

The Win32AppInventory configuration service provider is used to provide an inventory of installed applications on a device.

The following example shows the Win32AppInventory configuration service provider management objects in tree format as used by Open Mobile Alliance Device Management (OMA DM), OMA Client Provisioning, and Enterprise DM.

```
./Vendor/MSFT/Win32AppInventory
----Win32InstalledProgram
--------InstalledProgram
------------Name
------------Publisher
------------Version
------------Language
------------RegKey
------------Source
------------MsiProductCode
------------MsiPackageCode
```

**./Vendor/MSFT/Win32AppInventory** The root node for the Win32AppInventory configuration service provider.

The supported operation is Get.

**Win32InstalledProgram** This represents an inventory of installed Win32 applications on the device.

The supported operation is Get.

**Win32InstalledProgram/*InstalledProgram*** A node that contains information for a specific application.

**Win32InstalledProgram/*InstalledProgram*/Name** A string that specifies the name of the application.

The supported operation is Get.

**Win32InstalledProgram/*InstalledProgram*/Publisher** A string that specifies the publisher of the application.

The supported operation is Get.

**Win32InstalledProgram/*InstalledProgram*/Version** A string that specifies the version of the application.

The supported operation is Get.

**Win32InstalledProgram/*InstalledProgram*/Language** A string that specifies the language of the application.

The supported operation is Get.

**Win32InstalledProgram/*InstalledProgram*/RegKey** A string that specifies product code or registry subkey.

For MSI-based applications, this string is the product code.

For applications found in Add/Remove Programs, this string is the registry subkey.

The supported operation is Get.

**Win32InstalledProgram/*InstalledProgram*/Source** A string that specifies where the application was discovered, such as MSI or Add/Remove Programs.

The supported operation is Get.

**Win32InstalledProgram/*InstalledProgram*/MsiProductCode** A GUID that uniquely identifies a particular MSI product.

The supported operation is Get.

**Win32InstalledProgram/*InstalledProgram*/MsiPackageCode** A GUID that identifies an MSI package. Multiple products can make up a single package.

The supported operation is Get.