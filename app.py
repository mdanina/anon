import re
import gradio as gr
from gliner import GLiNER
from cerberus import Validator
from transformers import AutoTokenizer

# ----------------------------------------------------------------------------
# Load model + labels
# ----------------------------------------------------------------------------

model = GLiNER.from_pretrained("urchade/gliner_multi_pii-v1")
tokenizer = AutoTokenizer.from_pretrained("xlm-roberta-base")

with open("labels.txt", "r", encoding="utf-8") as f:
    labels = [line.strip() for line in f.readlines()]

MAX_TOKENS = 512  # безопасный лимит токенов на один фрагмент

# ----------------------------------------------------------------------------
# Simple Cerberus validation for incoming data
# ----------------------------------------------------------------------------

schema = {
    "text": {
        "type": "string",
        "empty": False
    }
}

validator = Validator(schema)

def validate_input(data: dict) -> str:
    if not validator.validate(data):
        raise ValueError(f"Invalid input data. Errors: {validator.errors}")
    return data["text"]

# ----------------------------------------------------------------------------
# Chunking + Anonymization logic
# ----------------------------------------------------------------------------

def split_text_into_chunks(text, max_tokens=MAX_TOKENS):
    words = text.split()
    chunks = []
    chunk = []
    chunk_token_count = 0
    current_offset = 0

    for word in words:
        token_count = len(tokenizer.tokenize(word))
        if chunk_token_count + token_count > max_tokens:
            chunk_text = ' '.join(chunk)
            chunks.append((chunk_text, current_offset))
            current_offset += len(chunk_text) + 1
            chunk = [word]
            chunk_token_count = token_count
        else:
            chunk.append(word)
            chunk_token_count += token_count

    if chunk:
        chunk_text = ' '.join(chunk)
        chunks.append((chunk_text, current_offset))

    return chunks

def anonymize_text_long(text):
    chunks = split_text_into_chunks(text)
    full_anonymized = ""
    global_entity_map = {}

    for chunk_text, _ in chunks:
        entities = model.predict_entities(chunk_text, labels=labels, threshold=0.2)
        entities.sort(key=lambda e: e['start'])

        anonymized_chunk = ""
        next_start = 0

        for entity in entities:
            label = entity['label'].replace(" ", "_").upper()
            original_text = entity['text']
            start_idx, end_idx = entity['start'], entity['end']

            if label not in global_entity_map:
                global_entity_map[label] = [original_text]
                idx = 1
            else:
                if original_text in global_entity_map[label]:
                    idx = global_entity_map[label].index(original_text) + 1
                else:
                    global_entity_map[label].append(original_text)
                    idx = len(global_entity_map[label])

            anonymized_chunk += chunk_text[next_start:start_idx]
            anonymized_chunk += f"<PII_{label}_{idx}>"
            next_start = end_idx

        anonymized_chunk += chunk_text[next_start:]
        full_anonymized += anonymized_chunk + " "

    return full_anonymized.strip(), global_entity_map

# ----------------------------------------------------------------------------
# De-anonymization logic
# ----------------------------------------------------------------------------

def deanonymize_text(anonymized_response, entity_map):
    def replace_match(match):
        label = match.group(1)
        idx_str = match.group(2)
        idx = int(idx_str) - 1
        if label in entity_map and 0 <= idx < len(entity_map[label]):
            return entity_map[label][idx]
        return match.group(0)

    pattern = r"<PII_(\w+)_(\d+)>"
    return re.sub(pattern, replace_match, anonymized_response)

# ----------------------------------------------------------------------------
# Gradio Interface
# ----------------------------------------------------------------------------

def anonymize_fn(original_text):
    data = {"text": original_text}
    try:
        user_text = validate_input(data)
    except ValueError as e:
        return "", {}, f"Validation error: {str(e)}"

    anonymized, entities = anonymize_text_long(user_text)
    return anonymized, entities, "Успешно анонимизировано!"

def deanonymize_fn(anonymized_llm_response, entity_map):
    if not anonymized_llm_response.strip():
        return "", "Вставьте анонимизированный текст."
    if not entity_map:
        return "", "No entity map found; anonymize some text first."

    result = deanonymize_text(anonymized_llm_response, entity_map)
    return result, "Успешно деанонимизировано!"

md_text = """# Анонимизатор психотерапевтических сессий

Вставьте текст в раздел \"Исходный текст\", чтобы анонимизировать сензитивные данные.
"""

with gr.Blocks() as demo:
    gr.Markdown(md_text)

    with gr.Row():
        with gr.Column():
            original_text = gr.Textbox(
                lines=6, label="Исходный текст (анонимизировать)"
            )
            anonymized_text = gr.Textbox(
                lines=6, label="Анонимизированный текст", interactive=False
            )
            button_anon = gr.Button("Анонимизировать")

            entity_map_state = gr.State()
            message_out = gr.Textbox(label="Status", interactive=False)

            button_anon.click(
                anonymize_fn,
                inputs=[original_text],
                outputs=[anonymized_text, entity_map_state, message_out]
            )

        with gr.Column():
            anonymized_llm_response = gr.Textbox(
                lines=6, label="Анонимизированная сессия (вставить)"
            )
            deanonymized_text = gr.Textbox(
                lines=6, label="Деанонимизированная сессия", interactive=False
            )
            button_deanon = gr.Button("Деанонимизировать")

            message_out_de = gr.Textbox(label="Status", interactive=False)

            button_deanon.click(
                deanonymize_fn,
                inputs=[anonymized_llm_response, entity_map_state],
                outputs=[deanonymized_text, message_out_de]
            )

if __name__ == "__main__":
    demo.launch()