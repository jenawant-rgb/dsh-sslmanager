// SSLManager expiry panel for the DSH Web Client.
//
// Hand-written module in the loader's format: no build step, no imports from
// other Harness packages (only React from the browser module table), so a
// missing chunk cannot blank the composer dock.
//
// When no credential is stored yet, the panel becomes the setup form: the
// token is posted to the host route, validated against SSLManager and written
// to the DSH credential store. It is never rendered back.
window.__ModuleLoader__.load({
  id: '@sslmanager/dsh-sslmanager',
  factory: (require) => {
    const React = require('react')
    const { useEffect, useState } = React

    const cardWidth =
      'calc(var(--dsh-composer-card-max-width, 780px) - 4 * var(--dsh-composer-dock-inset, 8px))'

    const styles = {
      // Match the composer card: the dock is a free-width flex child, so the
      // width has to come from the same variables the input card uses.
      bar: {
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        boxSizing: 'border-box',
        width: '100%',
        maxWidth: cardWidth,
        margin: '0 auto 6px',
        padding: '6px 10px',
        borderRadius: 8,
        border: '0.5px solid var(--dsw-alias-border-l1)',
        background: 'var(--dsw-alias-fill-l1)',
        fontSize: 12,
        lineHeight: '18px',
        color: 'var(--dsw-alias-label-secondary)',
      },
      dot: { width: 6, height: 6, borderRadius: 3, flex: 'none' },
      title: { fontWeight: 600, color: 'var(--dsw-alias-label-primary)' },
      spacer: { flex: 1 },
      button: {
        border: '0.5px solid var(--dsw-alias-border-l2)',
        background: 'transparent',
        color: 'var(--dsw-alias-label-secondary)',
        borderRadius: 6,
        padding: '2px 8px',
        fontSize: 11,
        cursor: 'pointer',
      },
      primaryButton: {
        border: '0.5px solid var(--dsw-alias-border-l2)',
        background: 'var(--dsw-alias-fill-l2)',
        color: 'var(--dsw-alias-label-primary)',
        borderRadius: 6,
        padding: '3px 12px',
        fontSize: 12,
        cursor: 'pointer',
      },
      panel: {
        boxSizing: 'border-box',
        width: '100%',
        maxWidth: cardWidth,
        margin: '0 auto 8px',
        border: '0.5px solid var(--dsw-alias-border-l1)',
        borderRadius: 8,
        background: 'var(--dsw-alias-fill-l2)',
        padding: 8,
        fontSize: 12,
      },
      row: {
        display: 'flex',
        alignItems: 'baseline',
        gap: 8,
        padding: '3px 2px',
        color: 'var(--dsw-alias-label-secondary)',
      },
      domain: { color: 'var(--dsw-alias-label-primary)', fontFamily: 'var(--dsw-font-mono)' },
      hint: { color: 'var(--dsw-alias-label-tertiary)', fontSize: 11 },
      input: {
        boxSizing: 'border-box',
        width: '100%',
        marginTop: 6,
        padding: '6px 8px',
        borderRadius: 6,
        border: '0.5px solid var(--dsw-alias-border-l2)',
        background: 'var(--dsw-alias-bg-base, #fff)',
        color: 'var(--dsw-alias-label-primary)',
        fontFamily: 'var(--dsw-font-mono)',
        fontSize: 12,
      },
      error: { color: 'var(--dsw-alias-state-error-primary)', fontSize: 11, marginTop: 6 },
    }

    function severity(days) {
      if (days <= 7) return 'var(--dsw-alias-state-error-primary)'
      if (days <= 21) return 'var(--dsw-alias-state-warning-primary, #d48806)'
      return 'var(--dsw-alias-state-success-primary, #389e0d)'
    }

    function ExpiryPanel() {
      const [state, setState] = useState({ status: 'loading', items: [], days: 45, at: null })
      const [open, setOpen] = useState(false)
      const [setupOpen, setSetupOpen] = useState(false)
      const [draft, setDraft] = useState('')
      const [saving, setSaving] = useState(false)
      const [saveError, setSaveError] = useState('')

      async function load() {
        setState((current) => ({ ...current, status: 'loading' }))
        try {
          const response = await fetch('/api/sslmanager/expiring?days=45', { credentials: 'same-origin' })
          if (!response.ok) throw new Error(`HTTP ${response.status}`)
          const body = await response.json()
          if (body.configured === false) {
            setState({ status: 'unconfigured', items: [], days: body.days || 45, at: null })
            setSetupOpen(true)
            return
          }
          setState({ status: 'ready', items: body.items || [], days: body.days || 45, at: body.generatedAt })
        } catch (error) {
          setState({ status: 'failed', items: [], days: 45, at: null, error: String(error.message || error) })
        }
      }

      useEffect(() => {
        load()
        const timer = setInterval(load, 10 * 60 * 1000)
        return () => clearInterval(timer)
      }, [])

      async function saveToken() {
        const token = draft.trim()
        if (!token) return
        setSaving(true)
        setSaveError('')
        try {
          const response = await fetch('/api/sslmanager/token', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ token }),
          })
          const body = await response.json().catch(() => ({}))
          if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`)
          setDraft('')
          setSetupOpen(false)
          await load()
        } catch (error) {
          setSaveError(String(error.message || error))
        } finally {
          setSaving(false)
        }
      }

      const setup = setupOpen
        ? React.createElement(
            'div',
            { style: styles.panel },
            React.createElement(
              'div',
              { style: styles.hint },
              '粘贴 SSLManager 访问令牌（控制台「访问令牌」页创建，至少需要 cert:read）。令牌只提交给本机 Harness 并存入凭据库，不会出现在对话里。',
            ),
            React.createElement('input', {
              type: 'password',
              autoFocus: true,
              placeholder: 'ssm_…',
              value: draft,
              style: styles.input,
              onChange: (event) => setDraft(event.target.value),
              onKeyDown: (event) => {
                if (event.key === 'Enter') saveToken()
              },
            }),
            React.createElement(
              'div',
              { style: { display: 'flex', gap: 8, marginTop: 8, alignItems: 'center' } },
              React.createElement(
                'button',
                { style: styles.primaryButton, disabled: saving || !draft.trim(), onClick: saveToken },
                saving ? '保存中…' : '保存令牌',
              ),
              React.createElement('button', { style: styles.button, onClick: () => setSetupOpen(false) }, '取消'),
              React.createElement('span', { style: styles.hint }, '保存前会先向 SSLManager 验证一次'),
            ),
            saveError ? React.createElement('div', { style: styles.error }, saveError) : null,
          )
        : null

      if (state.status === 'unconfigured') {
        return React.createElement(
          React.Fragment,
          null,
          React.createElement(
            'div',
            { style: styles.bar },
            React.createElement('span', {
              style: { ...styles.dot, background: 'var(--dsw-alias-state-warning-primary, #d48806)' },
            }),
            React.createElement('span', { style: styles.title }, 'SSLManager'),
            React.createElement('span', null, '还没有配置访问令牌'),
            React.createElement('span', { style: styles.spacer }),
            React.createElement(
              'button',
              { style: styles.button, onClick: () => setSetupOpen((value) => !value) },
              setupOpen ? '收起' : '填入令牌',
            ),
          ),
          setup,
        )
      }

      if (state.status === 'failed') {
        return React.createElement(
          React.Fragment,
          null,
          React.createElement(
            'div',
            { style: styles.bar },
            React.createElement('span', { style: { ...styles.dot, background: 'var(--dsw-alias-label-tertiary)' } }),
            React.createElement('span', { style: styles.title }, 'SSLManager'),
            React.createElement('span', null, '不可达'),
            React.createElement('span', { style: styles.spacer }),
            React.createElement('button', { style: styles.button, onClick: load }, '重试'),
            React.createElement(
              'button',
              { style: styles.button, onClick: () => setSetupOpen((value) => !value) },
              '设置',
            ),
          ),
          setup,
        )
      }

      const count = state.items.length
      const worst = count > 0 ? state.items[0].daysLeft : null
      const label =
        state.status === 'loading' && state.at === null
          ? '正在读取证书…'
          : count === 0
            ? `${state.days} 天内没有证书到期`
            : `${count} 张证书将在 ${state.days} 天内到期`

      return React.createElement(
        React.Fragment,
        null,
        React.createElement(
          'div',
          { style: styles.bar },
          React.createElement('span', {
            style: {
              ...styles.dot,
              background: worst === null ? 'var(--dsw-alias-state-success-primary, #389e0d)' : severity(worst),
            },
          }),
          React.createElement('span', { style: styles.title }, 'SSLManager'),
          React.createElement('span', null, label),
          count > 0 ? React.createElement('span', { style: styles.hint }, `最近 ${worst} 天`) : null,
          React.createElement('span', { style: styles.spacer }),
          React.createElement(
            'button',
            { style: styles.button, onClick: () => setSetupOpen((value) => !value) },
            '设置',
          ),
          React.createElement(
            'button',
            { style: styles.button, onClick: () => setOpen((value) => !value) },
            open ? '收起' : '查看',
          ),
        ),
        setup,
        open
          ? React.createElement(
              'div',
              { style: styles.panel },
              state.items.length === 0
                ? React.createElement('div', { style: styles.hint }, '没有即将到期的证书。')
                : state.items.map((item) =>
                    React.createElement(
                      'div',
                      { key: item.certId, style: styles.row },
                      React.createElement('span', { style: { ...styles.dot, background: severity(item.daysLeft) } }),
                      React.createElement('span', { style: styles.domain }, item.domain || `cert#${item.certId}`),
                      React.createElement('span', null, `${item.daysLeft} 天`),
                      React.createElement('span', { style: styles.hint }, item.deployed ? '已部署' : '未部署'),
                    ),
                  ),
              React.createElement(
                'div',
                { style: { ...styles.hint, marginTop: 6 } },
                '让助手续期：「把 xxx.com 的证书续一下并部署」',
              ),
            )
          : null,
      )
    }

    const inject = ['slots']

    function apply(ctx) {
      // One line so a missing panel can be diagnosed from the browser console.
      if (typeof console !== 'undefined') console.info('[sslmanager] dock panel registered')
      ctx.slots.inject('conversation.input.dock', () =>
        ctx.slots.register(
          {
            name: 'conversation.input.dock',
            id: 'sslmanager-expiry',
            order: 40,
          },
          ExpiryPanel,
        ),
      )
    }

    return { apply, inject }
  },
})
