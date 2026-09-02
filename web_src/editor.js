import {Compartment, EditorState, RangeSetBuilder} from '@codemirror/state';
import {
  Decoration,
  EditorView,
  ViewPlugin,
  drawSelection,
  dropCursor,
  highlightActiveLine,
  highlightSpecialChars,
  keymap,
  lineNumbers,
  placeholder,
  rectangularSelection
} from '@codemirror/view';
import {defaultKeymap, history, historyKeymap, indentWithTab} from '@codemirror/commands';
import {searchKeymap} from '@codemirror/search';

const LARGE_DOCUMENT = 500000;
const instances = new WeakMap();

const mark = className => Decoration.mark({class: className});
const marks = {
  method: mark('cm-http-method'),
  target: mark('cm-http-target'),
  version: mark('cm-http-version'),
  status: mark('cm-http-status'),
  header: mark('cm-http-header'),
  headerValue: mark('cm-http-header-value'),
  jsonKey: mark('cm-http-json-key'),
  jsonString: mark('cm-http-json-string'),
  jsonNumber: mark('cm-http-json-number'),
  jsonLiteral: mark('cm-http-json-literal')
};

function add(builder, from, to, decoration) {
  if (to > from) builder.add(from, to, decoration);
}

function decorateJSON(builder, line) {
  const token = /"(?:\\.|[^"\\])*"(?=\s*:)|"(?:\\.|[^"\\])*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|\b(?:true|false|null)\b/g;
  for (const match of line.text.matchAll(token)) {
    const value = match[0];
    const start = line.from + match.index;
    const rest = line.text.slice(match.index + value.length);
    const decoration = value.startsWith('"')
      ? (/^\s*:/.test(rest) ? marks.jsonKey : marks.jsonString)
      : (/^(true|false|null)$/.test(value) ? marks.jsonLiteral : marks.jsonNumber);
    add(builder, start, start + value.length, decoration);
  }
}

function httpDecorations(view) {
  const builder = new RangeSetBuilder();
  if (view.state.doc.length > LARGE_DOCUMENT) return builder.finish();
  let bodyLine = view.state.doc.lines + 1;
  for (let number = 1; number <= view.state.doc.lines; number++) {
    const line = view.state.doc.line(number);
    if (line.text === '') {
      bodyLine = number + 1;
      break;
    }
  }
  for (const range of view.visibleRanges) {
    let position = range.from;
    while (position <= range.to) {
      const line = view.state.doc.lineAt(position);
      if (line.number >= bodyLine) {
        decorateJSON(builder, line);
      } else if (line.number === 1) {
        const response = line.text.match(/^(HTTP\/\d(?:\.\d)?)(\s+)(\d{3})/);
        const request = line.text.match(/^([^\s]+)(\s+)(\S+)(\s+)(HTTP\/\d(?:\.\d)?)$/);
        if (response) {
          add(builder, line.from, line.from + response[1].length, marks.version);
          const statusStart = line.from + response[1].length + response[2].length;
          add(builder, statusStart, statusStart + response[3].length, marks.status);
        } else if (request) {
          let cursor = line.from;
          add(builder, cursor, cursor + request[1].length, marks.method);
          cursor += request[1].length + request[2].length;
          add(builder, cursor, cursor + request[3].length, marks.target);
          cursor += request[3].length + request[4].length;
          add(builder, cursor, cursor + request[5].length, marks.version);
        }
      } else {
        const colon = line.text.indexOf(':');
        if (colon > 0) {
          add(builder, line.from, line.from + colon, marks.header);
          add(builder, line.from + colon + 1, line.to, marks.headerValue);
        }
      }
      if (line.to >= range.to) break;
      position = line.to + 1;
    }
  }
  return builder.finish();
}

const httpHighlighter = ViewPlugin.fromClass(class {
  constructor(view) {
    this.decorations = httpDecorations(view);
  }
  update(update) {
    if (update.docChanged || update.viewportChanged) this.decorations = httpDecorations(update.view);
  }
}, {decorations: value => value.decorations});

const theme = EditorView.theme({
  '&': {
    height: '100%',
    color: '#34433c',
    backgroundColor: '#f7faf8',
    font: '13px/1.68 var(--mono)'
  },
  '&.cm-focused': {outline: 'none'},
  '.cm-scroller': {fontFamily: 'var(--mono)', overflow: 'auto'},
  '.cm-content': {padding: '18px 16px', caretColor: '#16221d'},
  '.cm-line': {padding: '0 4px'},
  '.cm-gutters': {
    borderRight: '1px solid #e2e9e5',
    backgroundColor: '#f2f6f4',
    color: '#91a099'
  },
  '.cm-activeLine, .cm-activeLineGutter': {backgroundColor: 'rgba(24,115,74,.045)'},
  '.cm-selectionBackground, &.cm-focused .cm-selectionBackground': {backgroundColor: 'rgba(72,135,221,.22)'},
  '.cm-cursor': {borderLeftColor: '#16221d'},
  '.cm-http-method': {color: '#19704d', fontWeight: '800'},
  '.cm-http-target': {color: '#316fa8'},
  '.cm-http-version': {color: '#71529b', fontWeight: '700'},
  '.cm-http-status': {color: '#19704d', fontWeight: '800'},
  '.cm-http-header': {color: '#7c4dba', fontWeight: '700'},
  '.cm-http-header-value': {color: '#1f6f8b'},
  '.cm-http-json-key': {color: '#2563a6', fontWeight: '700'},
  '.cm-http-json-string': {color: '#16805b'},
  '.cm-http-json-number': {color: '#c15a25'},
  '.cm-http-json-literal': {color: '#8a45a4', fontWeight: '700'}
});

function create(host, options = {}) {
  if (!host) return null;
  instances.get(host)?.destroy();
  host.replaceChildren();
  const editable = options.readOnly !== true;
  const readOnlyCompartment = new Compartment();
  let view;
  const extensions = [
    lineNumbers(),
    highlightSpecialChars(),
    history(),
    drawSelection(),
    dropCursor(),
    rectangularSelection(),
    highlightActiveLine(),
    keymap.of([...defaultKeymap, ...historyKeymap, ...searchKeymap, indentWithTab]),
    EditorView.lineWrapping,
    httpHighlighter,
    theme,
    readOnlyCompartment.of([
      EditorState.readOnly.of(!editable),
      EditorView.editable.of(editable)
    ])
  ];
  if (options.placeholder) extensions.push(placeholder(options.placeholder));
  if (typeof options.onChange === 'function') {
    extensions.push(EditorView.updateListener.of(update => {
      if (update.docChanged) options.onChange(update.state.doc.toString(), update);
    }));
  }
  view = new EditorView({
    state: EditorState.create({doc: String(options.value || ''), extensions}),
    parent: host
  });
  const api = {
    getValue: () => view.state.doc.toString(),
    setValue(value) {
      value = String(value || '');
      if (value === view.state.doc.toString()) return;
      view.dispatch({changes: {from: 0, to: view.state.doc.length, insert: value}});
    },
    setReadOnly(readOnly) {
      view.dispatch({effects: readOnlyCompartment.reconfigure([
        EditorState.readOnly.of(Boolean(readOnly)),
        EditorView.editable.of(!readOnly)
      ])});
    },
    focus: () => view.focus(),
    hasFocus: () => view.hasFocus,
    destroy() {
      view.destroy();
      instances.delete(host);
    },
    view
  };
  instances.set(host, api);
  return api;
}

function upgradeViewer(node) {
  if (!(node instanceof HTMLElement) || node.dataset.codeMirrorReady === 'true') return;
  node.dataset.codeMirrorReady = 'true';
  const value = node.textContent || '';
  const host = document.createElement('div');
  host.className = `${node.className} cm-http-viewer`;
  node.replaceWith(host);
  create(host, {value, readOnly: true});
}

function upgradeViewers(root = document) {
  root.querySelectorAll?.('[data-http-viewer]').forEach(upgradeViewer);
}

const observer = new MutationObserver(records => {
  for (const record of records) {
    for (const node of record.addedNodes) {
      if (!(node instanceof HTMLElement)) continue;
      if (node.matches?.('[data-http-viewer]')) upgradeViewer(node);
      upgradeViewers(node);
    }
  }
});

window.HappyScanEditor = {create, upgradeViewers};
document.addEventListener('DOMContentLoaded', () => {
  upgradeViewers();
  observer.observe(document.body, {childList: true, subtree: true});
});
