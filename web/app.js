/**
 * Therapy Session Anonymizer - Client-side Web Application
 * All data processing happens locally in the browser
 */

// ============================================
// State Management
// ============================================

const state = {
    entityMap: {},           // { TYPE: [value1, value2, ...] }
    detectedEntities: [],    // Array of { text, type, start, end }
    settings: {
        detectPhone: true,
        detectEmail: true,
        detectDate: true,
        detectPassport: true,
        detectInn: true,
        detectSnils: true,
        detectCard: true,
        detectIp: true,
        detectUrl: true,
        apiProvider: 'none',
        apiKey: ''
    }
};

// ============================================
// PII Detection Patterns (Regex)
// ============================================

const PII_PATTERNS = {
    // Russian phone numbers
    PHONE_NUMBER: [
        /(?:\+7|8)[\s-]?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}/g,
        /(?:\+7|8)\d{10}/g,
        /\b\d{3}[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}\b/g
    ],

    // Email addresses
    EMAIL: [
        /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g
    ],

    // Dates in various formats
    DATE: [
        /\b\d{1,2}[.\/\-]\d{1,2}[.\/\-]\d{2,4}\b/g,
        /\b\d{4}[.\/\-]\d{1,2}[.\/\-]\d{1,2}\b/g,
        /\b(?:января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря)\s+\d{1,2}(?:,?\s+\d{4})?\b/gi,
        /\b\d{1,2}\s+(?:января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря)(?:\s+\d{4})?\b/gi
    ],

    // Russian passport (series and number)
    PASSPORT_NUMBER: [
        /\b\d{2}\s?\d{2}\s?\d{6}\b/g,
        /паспорт[а-я]*\s*(?:серия\s*)?(\d{2}\s?\d{2})\s*(?:№|номер|н\.)?\s*(\d{6})/gi
    ],

    // Russian INN (tax ID)
    NATIONAL_ID_NUMBER: [
        /\bИНН\s*:?\s*\d{10,12}\b/gi,
        /\b\d{10}\b(?=\s*(?:инн|ИНН))/g
    ],

    // Russian SNILS (social security)
    INSURANCE_NUMBER: [
        /\b\d{3}[\s-]?\d{3}[\s-]?\d{3}[\s-]?\d{2}\b/g,
        /СНИЛС\s*:?\s*\d{3}[\s-]?\d{3}[\s-]?\d{3}[\s-]?\d{2}/gi
    ],

    // Credit/debit card numbers
    CREDIT_CARD_NUMBER: [
        /\b(?:\d{4}[\s-]?){3}\d{4}\b/g,
        /\b\d{16}\b/g
    ],

    // IP addresses
    IP_ADDRESS: [
        /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g
    ],

    // URLs
    URL: [
        /https?:\/\/[^\s<>"{}|\\^`\[\]]+/g,
        /www\.[^\s<>"{}|\\^`\[\]]+/g
    ]
};

// Map settings keys to pattern types
const SETTING_TO_PATTERN = {
    detectPhone: 'PHONE_NUMBER',
    detectEmail: 'EMAIL',
    detectDate: 'DATE',
    detectPassport: 'PASSPORT_NUMBER',
    detectInn: 'NATIONAL_ID_NUMBER',
    detectSnils: 'INSURANCE_NUMBER',
    detectCard: 'CREDIT_CARD_NUMBER',
    detectIp: 'IP_ADDRESS',
    detectUrl: 'URL'
};

// PII type categories for styling
const PII_CATEGORIES = {
    PERSON: 'person',
    FULL_NAME: 'person',
    FIRST_NAME: 'person',
    LAST_NAME: 'person',
    NICKNAME: 'person',
    AGE: 'person',
    DATE_OF_BIRTH: 'person',
    FAMILY_MEMBER: 'person',
    THERAPIST_NAME: 'person',

    PHONE_NUMBER: 'contact',
    EMAIL: 'contact',
    EMAIL_ADDRESS: 'contact',

    ADDRESS: 'location',
    CITY: 'location',
    COUNTRY: 'location',
    LOCATION: 'location',
    POSTAL_CODE: 'location',

    PASSPORT_NUMBER: 'id',
    NATIONAL_ID_NUMBER: 'id',
    DRIVER_LICENSE_NUMBER: 'id',
    INSURANCE_NUMBER: 'id',

    BANK_ACCOUNT: 'financial',
    CREDIT_CARD_NUMBER: 'financial',

    ORGANIZATION: 'org',
    EMPLOYER: 'org',
    SCHOOL: 'org',
    UNIVERSITY: 'org',

    DATE: 'id',
    IP_ADDRESS: 'contact',
    URL: 'contact',
    USERNAME: 'contact',
    SOCIAL_MEDIA_HANDLE: 'contact'
};

// ============================================
// Core Anonymization Logic
// ============================================

/**
 * Detect PII entities using regex patterns
 */
function detectPIIWithRegex(text) {
    const entities = [];
    const usedRanges = []; // To avoid overlapping matches

    // Check each enabled pattern type
    for (const [settingKey, patternType] of Object.entries(SETTING_TO_PATTERN)) {
        if (!state.settings[settingKey]) continue;

        const patterns = PII_PATTERNS[patternType];
        if (!patterns) continue;

        for (const pattern of patterns) {
            // Reset regex lastIndex
            pattern.lastIndex = 0;

            let match;
            while ((match = pattern.exec(text)) !== null) {
                const start = match.index;
                const end = match.index + match[0].length;
                const matchText = match[0];

                // Check for overlap with existing entities
                const overlaps = usedRanges.some(range =>
                    (start >= range.start && start < range.end) ||
                    (end > range.start && end <= range.end) ||
                    (start <= range.start && end >= range.end)
                );

                if (!overlaps && matchText.trim().length > 0) {
                    entities.push({
                        text: matchText,
                        type: patternType,
                        start: start,
                        end: end
                    });
                    usedRanges.push({ start, end });
                }
            }
        }
    }

    // Sort by start position
    entities.sort((a, b) => a.start - b.start);

    return entities;
}

/**
 * Add a manually selected entity
 */
function addManualEntity(text, type, start, end) {
    // Check for duplicates
    const exists = state.detectedEntities.some(e =>
        e.start === start && e.end === end
    );

    if (!exists && text.trim().length > 0) {
        state.detectedEntities.push({ text, type, start, end });
        state.detectedEntities.sort((a, b) => a.start - b.start);
        return true;
    }
    return false;
}

/**
 * Remove an entity by index
 */
function removeEntity(index) {
    if (index >= 0 && index < state.detectedEntities.length) {
        state.detectedEntities.splice(index, 1);
    }
}

/**
 * Build entity map and anonymize text
 */
function anonymizeText(text, entities) {
    state.entityMap = {};
    let anonymized = '';
    let lastEnd = 0;

    for (const entity of entities) {
        const { text: entityText, type, start, end } = entity;

        // Add text before this entity
        anonymized += text.substring(lastEnd, start);

        // Get or create index for this entity
        if (!state.entityMap[type]) {
            state.entityMap[type] = [];
        }

        let idx = state.entityMap[type].indexOf(entityText);
        if (idx === -1) {
            state.entityMap[type].push(entityText);
            idx = state.entityMap[type].length - 1;
        }

        // Replace with token
        anonymized += `<PII_${type}_${idx + 1}>`;
        lastEnd = end;
    }

    // Add remaining text
    anonymized += text.substring(lastEnd);

    return anonymized;
}

/**
 * Deanonymize text using entity map
 */
function deanonymizeText(text, entityMap) {
    const pattern = /<PII_(\w+)_(\d+)>/g;

    return text.replace(pattern, (match, type, idxStr) => {
        const idx = parseInt(idxStr, 10) - 1;
        if (entityMap[type] && idx >= 0 && idx < entityMap[type].length) {
            return entityMap[type][idx];
        }
        return match; // Keep original if not found
    });
}

/**
 * Format anonymized text with highlighted PII tags
 */
function formatAnonymizedText(text) {
    const pattern = /<PII_(\w+)_(\d+)>/g;

    return text.replace(pattern, (match, type, idx) => {
        const category = PII_CATEGORIES[type] || 'id';
        const title = `${type.replace(/_/g, ' ')} #${idx}`;
        return `<span class="pii-tag ${category}" title="${title}">${match}</span>`;
    });
}

// ============================================
// LLM API Integration (Optional)
// ============================================

const LLM_PROMPT = `Analyze the following text and identify all personally identifiable information (PII).
Return a JSON array of objects with the following structure:
[{"text": "found PII text", "type": "PII_TYPE", "start": start_index, "end": end_index}]

PII types to look for:
- PERSON, FULL_NAME, FIRST_NAME, LAST_NAME - names of people
- THERAPIST_NAME - therapist/doctor names
- AGE, DATE_OF_BIRTH - age-related info
- PHONE_NUMBER, EMAIL, EMAIL_ADDRESS - contact info
- ADDRESS, CITY, COUNTRY, POSTAL_CODE - location info
- ORGANIZATION, EMPLOYER, SCHOOL, UNIVERSITY - organizations
- PASSPORT_NUMBER, NATIONAL_ID_NUMBER, DRIVER_LICENSE_NUMBER - IDs
- BANK_ACCOUNT, CREDIT_CARD_NUMBER - financial info
- DATE - specific dates
- USERNAME, SOCIAL_MEDIA_HANDLE, URL - online identifiers

Text to analyze:
`;

async function detectPIIWithLLM(text) {
    const { apiProvider, apiKey } = state.settings;

    if (apiProvider === 'none' || !apiKey) {
        throw new Error('API не настроен');
    }

    let response;

    if (apiProvider === 'anthropic') {
        response = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': apiKey,
                'anthropic-version': '2023-06-01',
                'anthropic-dangerous-direct-browser-access': 'true'
            },
            body: JSON.stringify({
                model: 'claude-sonnet-4-20250514',
                max_tokens: 4096,
                messages: [{
                    role: 'user',
                    content: LLM_PROMPT + text
                }]
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error?.message || 'Ошибка API Anthropic');
        }

        const data = await response.json();
        const content = data.content[0].text;

        // Extract JSON from response
        const jsonMatch = content.match(/\[[\s\S]*\]/);
        if (jsonMatch) {
            return JSON.parse(jsonMatch[0]);
        }
        return [];

    } else if (apiProvider === 'openai') {
        response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`
            },
            body: JSON.stringify({
                model: 'gpt-4o-mini',
                messages: [{
                    role: 'user',
                    content: LLM_PROMPT + text
                }],
                temperature: 0
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error?.message || 'Ошибка API OpenAI');
        }

        const data = await response.json();
        const content = data.choices[0].message.content;

        // Extract JSON from response
        const jsonMatch = content.match(/\[[\s\S]*\]/);
        if (jsonMatch) {
            return JSON.parse(jsonMatch[0]);
        }
        return [];
    }

    throw new Error('Неизвестный API-провайдер');
}

// ============================================
// Storage Functions
// ============================================

function saveToStorage() {
    try {
        localStorage.setItem('anonymizer_entityMap', JSON.stringify(state.entityMap));
        localStorage.setItem('anonymizer_settings', JSON.stringify(state.settings));
    } catch (e) {
        console.error('Failed to save to localStorage:', e);
    }
}

function loadFromStorage() {
    try {
        const entityMap = localStorage.getItem('anonymizer_entityMap');
        const settings = localStorage.getItem('anonymizer_settings');

        if (entityMap) {
            state.entityMap = JSON.parse(entityMap);
        }
        if (settings) {
            state.settings = { ...state.settings, ...JSON.parse(settings) };
        }
    } catch (e) {
        console.error('Failed to load from localStorage:', e);
    }
}

function clearStorage() {
    try {
        localStorage.removeItem('anonymizer_entityMap');
        localStorage.removeItem('anonymizer_settings');
        state.entityMap = {};
        state.detectedEntities = [];
    } catch (e) {
        console.error('Failed to clear localStorage:', e);
    }
}

// ============================================
// UI Functions
// ============================================

function showNotification(message, type = 'info') {
    const notification = document.getElementById('notification');
    notification.textContent = message;
    notification.className = `notification visible ${type}`;

    setTimeout(() => {
        notification.classList.remove('visible');
    }, 3000);
}

function updateEntityList() {
    const entityList = document.getElementById('entityList');
    const entityItems = document.getElementById('entityItems');
    const entityCount = document.getElementById('entityCount');

    if (state.detectedEntities.length === 0) {
        entityList.style.display = 'none';
        return;
    }

    entityList.style.display = 'block';
    entityCount.textContent = state.detectedEntities.length;

    entityItems.innerHTML = state.detectedEntities.map((entity, index) => {
        const category = PII_CATEGORIES[entity.type] || 'id';
        const typeLabel = entity.type.replace(/_/g, ' ');

        // Find index in entityMap for token display
        let tokenIdx = 1;
        if (state.entityMap[entity.type]) {
            const idx = state.entityMap[entity.type].indexOf(entity.text);
            if (idx !== -1) tokenIdx = idx + 1;
        }

        return `
            <div class="entity-item">
                <div class="entity-item-left">
                    <span class="entity-type">${typeLabel}</span>
                    <span class="entity-value">${escapeHtml(entity.text)}</span>
                </div>
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <span class="entity-token">&lt;PII_${entity.type}_${tokenIdx}&gt;</span>
                    <button class="entity-remove" data-index="${index}" title="Удалить">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M18 6L6 18M6 6l12 12"/>
                        </svg>
                    </button>
                </div>
            </div>
        `;
    }).join('');

    // Add click handlers for remove buttons
    entityItems.querySelectorAll('.entity-remove').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const index = parseInt(e.currentTarget.dataset.index, 10);
            removeEntity(index);
            updateEntityList();
            // Re-run anonymization to update output
            const inputText = document.getElementById('inputText').value;
            if (inputText && state.detectedEntities.length > 0) {
                const anonymized = anonymizeText(inputText, state.detectedEntities);
                document.getElementById('outputText').innerHTML = formatAnonymizedText(anonymized);
                saveToStorage();
            }
        });
    });
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function downloadFile(content, filename, type = 'text/plain') {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function applySettings() {
    // Load settings checkboxes
    for (const [key, value] of Object.entries(state.settings)) {
        const checkbox = document.getElementById(`detect-${key.replace('detect', '').toLowerCase()}`);
        if (checkbox) {
            checkbox.checked = value;
        }
    }

    // API settings
    document.getElementById('apiProvider').value = state.settings.apiProvider;
    document.getElementById('apiKey').value = state.settings.apiKey;
    document.getElementById('apiKeyGroup').style.display =
        state.settings.apiProvider !== 'none' ? 'block' : 'none';
}

function collectSettings() {
    // Collect checkbox settings
    for (const settingKey of Object.keys(SETTING_TO_PATTERN)) {
        const checkboxId = `detect-${settingKey.replace('detect', '').toLowerCase()}`;
        const checkbox = document.getElementById(checkboxId);
        if (checkbox) {
            state.settings[settingKey] = checkbox.checked;
        }
    }

    // API settings
    state.settings.apiProvider = document.getElementById('apiProvider').value;
    state.settings.apiKey = document.getElementById('apiKey').value;

    saveToStorage();
}

// ============================================
// Sample Text
// ============================================

const SAMPLE_TEXT = `Сессия от 15.03.2024
Клиент: Иван Петрович Сидоров
Терапевт: Мария Александровна Козлова

И.П. (клиент): На прошлой неделе я снова поссорился с женой, Еленой. Она работает в компании "Газпром Нефть" и постоянно задерживается допоздна. Мой номер телефона +7 (495) 123-45-67, если что-то срочное.

М.А.: Расскажите подробнее о вашей работе. Вы упоминали, что работаете в IT.

И.П.: Да, я работаю программистом в Яндексе, офис на улице Льва Толстого, 16. Моя зарплата поступает на карту 4276 1234 5678 9012. Мне 34 года, родился 25 февраля 1990 года.

М.А.: А как обстоят дела с вашим сыном Димой? Вы упоминали проблемы в школе №1543.

И.П.: Дима сейчас в 5 классе. Учительница, Анна Сергеевна Белова, говорит, что он отвлекается. Мой email: ivan.sidorov@yandex.ru, туда присылают уведомления из школы.

Контакт для экстренной связи: мама клиента, Ольга Николаевна Сидорова, тел. 8-916-765-43-21.
Паспорт клиента: 45 12 345678
ИНН: 7707083893
СНИЛС: 123-456-789-01`;

// ============================================
// Event Handlers
// ============================================

document.addEventListener('DOMContentLoaded', () => {
    // Load saved data
    loadFromStorage();
    applySettings();

    // Tab switching
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

            tab.classList.add('active');
            document.getElementById(`tab-${tab.dataset.tab}`).classList.add('active');
        });
    });

    // Input text - selection menu
    const inputText = document.getElementById('inputText');
    const selectionMenu = document.getElementById('selectionMenu');

    inputText.addEventListener('mouseup', (e) => {
        const selection = window.getSelection();
        const selectedText = selection.toString().trim();

        if (selectedText.length > 0) {
            const range = selection.getRangeAt(0);
            const rect = range.getBoundingClientRect();

            // Position menu near selection
            selectionMenu.style.left = `${rect.left + window.scrollX}px`;
            selectionMenu.style.top = `${rect.bottom + window.scrollY + 5}px`;
            selectionMenu.classList.add('visible');

            // Store selection info
            selectionMenu.dataset.text = selectedText;
            selectionMenu.dataset.start = inputText.selectionStart;
            selectionMenu.dataset.end = inputText.selectionEnd;
        } else {
            selectionMenu.classList.remove('visible');
        }
    });

    // Hide menu on click outside
    document.addEventListener('click', (e) => {
        if (!selectionMenu.contains(e.target) && e.target !== inputText) {
            selectionMenu.classList.remove('visible');
        }
    });

    // Selection menu buttons
    selectionMenu.querySelectorAll('button').forEach(btn => {
        btn.addEventListener('click', () => {
            const text = selectionMenu.dataset.text;
            const start = parseInt(selectionMenu.dataset.start, 10);
            const end = parseInt(selectionMenu.dataset.end, 10);
            const type = btn.dataset.type;

            if (addManualEntity(text, type, start, end)) {
                showNotification(`Добавлено: ${text} (${type})`, 'success');
                updateEntityList();
            }

            selectionMenu.classList.remove('visible');
        });
    });

    // Auto-detect button
    document.getElementById('autoDetectBtn').addEventListener('click', async () => {
        const text = inputText.value;
        if (!text.trim()) {
            showNotification('Введите текст для анализа', 'error');
            return;
        }

        try {
            // First, detect with regex
            const regexEntities = detectPIIWithRegex(text);

            // Merge with existing manually added entities
            for (const entity of regexEntities) {
                addManualEntity(entity.text, entity.type, entity.start, entity.end);
            }

            // If LLM API is configured, use it too
            if (state.settings.apiProvider !== 'none' && state.settings.apiKey) {
                showNotification('Запрос к LLM API...', 'info');
                try {
                    const llmEntities = await detectPIIWithLLM(text);
                    for (const entity of llmEntities) {
                        addManualEntity(entity.text, entity.type, entity.start, entity.end);
                    }
                } catch (e) {
                    showNotification(`Ошибка LLM: ${e.message}`, 'error');
                }
            }

            updateEntityList();
            showNotification(`Найдено ${state.detectedEntities.length} сущностей`, 'success');

        } catch (e) {
            showNotification(`Ошибка: ${e.message}`, 'error');
        }
    });

    // Anonymize button
    document.getElementById('anonymizeBtn').addEventListener('click', () => {
        const text = inputText.value;
        if (!text.trim()) {
            showNotification('Введите текст для анонимизации', 'error');
            return;
        }

        // If no entities detected, run auto-detection first
        if (state.detectedEntities.length === 0) {
            const regexEntities = detectPIIWithRegex(text);
            for (const entity of regexEntities) {
                addManualEntity(entity.text, entity.type, entity.start, entity.end);
            }
        }

        if (state.detectedEntities.length === 0) {
            showNotification('Не найдено персональных данных. Выделите текст вручную.', 'error');
            return;
        }

        const anonymized = anonymizeText(text, state.detectedEntities);
        document.getElementById('outputText').innerHTML = formatAnonymizedText(anonymized);

        updateEntityList();
        saveToStorage();

        showNotification('Текст анонимизирован', 'success');
    });

    // Copy result button
    document.getElementById('copyResultBtn').addEventListener('click', () => {
        const output = document.getElementById('outputText');
        const text = output.innerText || output.textContent;

        if (text.includes('Результат анонимизации появится здесь')) {
            showNotification('Сначала анонимизируйте текст', 'error');
            return;
        }

        navigator.clipboard.writeText(text).then(() => {
            showNotification('Скопировано в буфер обмена', 'success');
        }).catch(() => {
            showNotification('Не удалось скопировать', 'error');
        });
    });

    // Download result button
    document.getElementById('downloadResultBtn').addEventListener('click', () => {
        const output = document.getElementById('outputText');
        const text = output.innerText || output.textContent;

        if (text.includes('Результат анонимизации появится здесь')) {
            showNotification('Сначала анонимизируйте текст', 'error');
            return;
        }

        const timestamp = new Date().toISOString().slice(0, 10);
        downloadFile(text, `anonymized_${timestamp}.txt`);
        showNotification('Файл скачан', 'success');
    });

    // Export mapping button
    document.getElementById('exportMapBtn').addEventListener('click', () => {
        if (Object.keys(state.entityMap).length === 0) {
            showNotification('Нет данных для экспорта', 'error');
            return;
        }

        const json = JSON.stringify(state.entityMap, null, 2);
        const timestamp = new Date().toISOString().slice(0, 10);
        downloadFile(json, `entity_map_${timestamp}.json`, 'application/json');
        showNotification('Маппинг экспортирован', 'success');
    });

    // Load sample button
    document.getElementById('loadSampleBtn').addEventListener('click', () => {
        inputText.value = SAMPLE_TEXT;
        state.detectedEntities = [];
        document.getElementById('outputText').innerHTML = `
            <div class="empty-state">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                    <path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                </svg>
                <p>Результат анонимизации появится здесь</p>
            </div>
        `;
        updateEntityList();
        showNotification('Пример загружен', 'success');
    });

    // Clear input button
    document.getElementById('clearInputBtn').addEventListener('click', () => {
        inputText.value = '';
        state.detectedEntities = [];
        document.getElementById('outputText').innerHTML = `
            <div class="empty-state">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                    <path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                </svg>
                <p>Результат анонимизации появится здесь</p>
            </div>
        `;
        updateEntityList();
    });

    // Deanonymize button
    document.getElementById('deanonymizeBtn').addEventListener('click', () => {
        const text = document.getElementById('deanonInput').value;
        if (!text.trim()) {
            showNotification('Введите анонимизированный текст', 'error');
            return;
        }

        if (Object.keys(state.entityMap).length === 0) {
            showNotification('Нет маппинга. Сначала анонимизируйте текст или импортируйте маппинг.', 'error');
            return;
        }

        const deanonymized = deanonymizeText(text, state.entityMap);
        document.getElementById('deanonOutput').textContent = deanonymized;

        showNotification('Текст деанонимизирован', 'success');
    });

    // Copy deanonymized button
    document.getElementById('copyDeanonBtn').addEventListener('click', () => {
        const output = document.getElementById('deanonOutput');
        const text = output.innerText || output.textContent;

        if (text.includes('Восстановленный текст появится здесь')) {
            showNotification('Сначала деанонимизируйте текст', 'error');
            return;
        }

        navigator.clipboard.writeText(text).then(() => {
            showNotification('Скопировано в буфер обмена', 'success');
        }).catch(() => {
            showNotification('Не удалось скопировать', 'error');
        });
    });

    // Import mapping button
    document.getElementById('importMapBtn').addEventListener('click', () => {
        document.getElementById('importModal').classList.add('visible');
    });

    // Cancel import
    document.getElementById('cancelImportBtn').addEventListener('click', () => {
        document.getElementById('importModal').classList.remove('visible');
        document.getElementById('importMapText').value = '';
    });

    // Confirm import
    document.getElementById('confirmImportBtn').addEventListener('click', () => {
        const text = document.getElementById('importMapText').value;

        try {
            const imported = JSON.parse(text);
            state.entityMap = imported;
            saveToStorage();

            document.getElementById('importModal').classList.remove('visible');
            document.getElementById('importMapText').value = '';

            showNotification('Маппинг импортирован', 'success');
        } catch (e) {
            showNotification('Неверный формат JSON', 'error');
        }
    });

    // Import file
    document.getElementById('importMapFile').addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = (event) => {
            document.getElementById('importMapText').value = event.target.result;
        };
        reader.readAsText(file);
    });

    // API provider change
    document.getElementById('apiProvider').addEventListener('change', (e) => {
        state.settings.apiProvider = e.target.value;
        document.getElementById('apiKeyGroup').style.display =
            e.target.value !== 'none' ? 'block' : 'none';
        saveToStorage();
    });

    // Save API key
    document.getElementById('saveApiKeyBtn').addEventListener('click', () => {
        state.settings.apiKey = document.getElementById('apiKey').value;
        saveToStorage();
        showNotification('API-ключ сохранён', 'success');
    });

    // Settings checkboxes
    document.querySelectorAll('.settings-section input[type="checkbox"]').forEach(checkbox => {
        checkbox.addEventListener('change', collectSettings);
    });

    // Clear storage
    document.getElementById('clearStorageBtn').addEventListener('click', () => {
        if (confirm('Удалить все сохранённые данные?')) {
            clearStorage();
            applySettings();
            showNotification('Данные очищены', 'success');
        }
    });
});
