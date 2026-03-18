# MCP Tool Inventory and Local Security Review

This inventory was generated from all `@server.tool()` declarations in this repository.


## Security baseline for local deployment
- Bind transport to localhost only; do not expose the MCP port on LAN/WAN unless behind authenticated reverse proxy.
- Use least-privilege Google OAuth scopes (or permissions mode / read-only mode) to reduce blast radius.
- Protect OAuth client secret, refresh tokens, and any attachment cache/storage on disk.
- Enable logging/monitoring for tool invocations, especially write/delete/share/send actions.
- Restrict high-risk tools (Apps Script execution, Drive permission changes, outbound email/send actions) when not required.

## Apps Script tools (15)
| Tool | Risk | Security concern |
|---|---|---|
| `create_script_project` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `create_version` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `delete_script_project` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `generate_trigger_code` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `get_script_content` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `get_script_metrics` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `get_script_project` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `get_version` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `list_deployments` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `list_script_processes` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `list_script_projects` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `list_versions` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `manage_deployment` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `run_script_function` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `update_script_content` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |

## Calendar tools (4)
| Tool | Risk | Security concern |
|---|---|---|
| `get_events` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `list_calendars` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `manage_event` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `query_freebusy` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |

## Chat tools (6)
| Tool | Risk | Security concern |
|---|---|---|
| `create_reaction` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `download_chat_attachment` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `get_messages` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `list_spaces` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `search_messages` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `send_message` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |

## Contacts tools (8)
| Tool | Risk | Security concern |
|---|---|---|
| `get_contact` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `get_contact_group` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `list_contact_groups` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `list_contacts` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `manage_contact` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `manage_contact_group` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `manage_contacts_batch` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `search_contacts` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |

## Core Auth tools (1)
| Tool | Risk | Security concern |
|---|---|---|
| `start_google_auth` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |

## Custom Search tools (2)
| Tool | Risk | Security concern |
|---|---|---|
| `get_search_engine_info` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `search_custom` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |

## Docs tools (19)
| Tool | Risk | Security concern |
|---|---|---|
| `batch_update_doc` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `create_doc` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `create_table_with_data` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `debug_table_structure` | Medium | Evaluate per OAuth scope and returned data sensitivity. |
| `delete_doc_tab` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `export_doc_to_pdf` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `find_and_replace_doc` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `get_doc_as_markdown` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `get_doc_content` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `insert_doc_elements` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `insert_doc_image` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `insert_doc_tab` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `inspect_doc_structure` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `list_docs_in_folder` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `modify_doc_text` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `search_docs` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `update_doc_headers_footers` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `update_doc_tab` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `update_paragraph_style` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |

## Drive tools (14)
| Tool | Risk | Security concern |
|---|---|---|
| `check_drive_file_public_access` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `copy_drive_file` | Medium | Evaluate per OAuth scope and returned data sensitivity. |
| `create_drive_file` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `create_drive_folder` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `get_drive_file_content` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `get_drive_file_download_url` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `get_drive_file_permissions` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `get_drive_shareable_link` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `import_to_google_doc` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `list_drive_items` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `manage_drive_access` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `search_drive_files` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `set_drive_file_permissions` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `update_drive_file` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |

## Forms tools (6)
| Tool | Risk | Security concern |
|---|---|---|
| `batch_update_form` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `create_form` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `get_form` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `get_form_response` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `list_form_responses` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `set_publish_settings` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |

## Gmail tools (14)
| Tool | Risk | Security concern |
|---|---|---|
| `batch_modify_gmail_message_labels` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `draft_gmail_message` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `get_gmail_attachment_content` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `get_gmail_message_content` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `get_gmail_messages_content_batch` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `get_gmail_thread_content` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `get_gmail_threads_content_batch` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `list_gmail_filters` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `list_gmail_labels` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `manage_gmail_filter` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `manage_gmail_label` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `modify_gmail_message_labels` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `search_gmail_messages` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `send_gmail_message` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |

## Sheets tools (8)
| Tool | Risk | Security concern |
|---|---|---|
| `create_sheet` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `create_spreadsheet` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `format_sheet_range` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `get_spreadsheet_info` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `list_spreadsheets` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `manage_conditional_formatting` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `modify_sheet_values` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `read_sheet_values` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |

## Slides tools (5)
| Tool | Risk | Security concern |
|---|---|---|
| `batch_update_presentation` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `create_presentation` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `get_page` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `get_page_thumbnail` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `get_presentation` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |

## Tasks tools (6)
| Tool | Risk | Security concern |
|---|---|---|
| `get_task` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `get_task_list` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `list_task_lists` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `list_tasks` | Medium | Read access can expose sensitive workspace data; enforce least-privilege scopes and auditing. |
| `manage_task` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |
| `manage_task_list` | High | Can modify data, trigger automation, or increase data-sharing/exfiltration risk if abused. |

