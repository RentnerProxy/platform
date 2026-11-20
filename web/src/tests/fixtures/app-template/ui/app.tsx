import { createRoot } from 'react-dom/client'

import { maxGreetingLength } from '../greeting.ts'
import { useGreetingLogic } from './useGreetingLogic.ts'

function Greeting() {
    const { state, handler, setter } = useGreetingLogic()
    const { labels } = state
    return (
        <main>
            <h1>{labels.app}</h1>
            <nav aria-label={labels.app}>
                <button
                    aria-current={state.route === 'overview' ? 'page' : undefined}
                    disabled={!state.ready}
                    type="button"
                    onClick={() => handler.navigate('overview')}
                >
                    {labels.overview}
                </button>
                <button
                    aria-current={state.route === 'details' ? 'page' : undefined}
                    disabled={!state.ready}
                    type="button"
                    onClick={() => handler.navigate('details')}
                >
                    {labels.details}
                </button>
            </nav>
            {state.route === 'details' ? (
                <p>{labels.detailsText}</p>
            ) : (
                <section aria-label={labels.app}>
                    <p className="greeting">{state.greeting}</p>
                    <label htmlFor="greeting">{labels.field}</label>
                    <input
                        id="greeting"
                        disabled={!state.ready || state.busy}
                        value={state.draft}
                        maxLength={maxGreetingLength}
                        onChange={(event) => setter.setDraft(event.currentTarget.value)}
                        onKeyDown={(event) => {
                            if (event.key === 'Enter') void handler.save()
                        }}
                    />
                    <button
                        disabled={state.disabled}
                        type="button"
                        onClick={() => {
                            void handler.save()
                        }}
                    >
                        {labels.save}
                    </button>
                    <output>
                        {state.status
                            ? labels[state.status]
                            : state.busy
                              ? labels.busy
                              : !state.ready
                                ? labels.waiting
                                : ''}
                    </output>
                </section>
            )}
        </main>
    )
}

const container = document.getElementById('root')
if (!container) throw new Error('Greeting mount is missing')
createRoot(container).render(<Greeting />)
