// SSLManager expiry panel for the DSH Web Client.
//
// Hand-written module in the loader's format: no build step, no imports from
// other Harness packages (only React from the browser module table), so a
// missing chunk cannot blank the composer dock.
window.__ModuleLoader__.load({
  id: '@sslmanager/dsh-sslmanager',
  factory: (require) => {
    const React = require('react')
    const { useEffect, useState } = React

    const styles = {
      bar: {
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        margin: '0 12px 6px',
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
      panel: {
        margin: '0 12px 8px',
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
    }

    function severity(days) {
      if (days <= 7) return 'var(--dsw-alias-state-error-primary)'
      if (days <= 21) return 'var(--dsw-alias-state-warning-primary, #d48806)'
      return 'var(--dsw-alias-state-success-primary, #389e0d)'
    }

    function ExpiryPanel() {
      const [state, setState] = useState({ status: 'loading', items: [], days: 45, at: null })
      const [open, setOpen] = useState(false)

      async function load() {
        setState((current) => ({ ...current, status: 'loading' }))
        try {
          const response = await fetch('/api/sslmanager/expiring?days=45', { credentials: 'same-origin' })
          if (!response.ok) throw new Error(`HTTP ${response.status}`)
          const body = await response.json()
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

      if (state.status === 'failed') {
        return React.createElement(
          'div',
          { style: styles.bar },
          React.createElement('span', { style: { ...styles.dot, background: 'var(--dsw-alias-label-tertiary)' } }),
          React.createElement('span', { style: styles.title }, 'SSLManager'),
          React.createElement('span', null, '未配置或不可达'),
          React.createElement('span', { style: styles.spacer }),
          React.createElement('button', { style: styles.button, onClick: load }, '重试'),
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
            style: { ...styles.dot, background: worst === null ? 'var(--dsw-alias-state-success-primary, #389e0d)' : severity(worst) },
          }),
          React.createElement('span', { style: styles.title }, 'SSLManager'),
          React.createElement('span', null, label),
          count > 0 ? React.createElement('span', { style: styles.hint }, `最近 ${worst} 天`) : null,
          React.createElement('span', { style: styles.spacer }),
          React.createElement(
            'button',
            { style: styles.button, onClick: () => setOpen((value) => !value) },
            open ? '收起' : '查看',
          ),
        ),
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
