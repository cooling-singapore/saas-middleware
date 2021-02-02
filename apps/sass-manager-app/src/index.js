import React from 'react';
import ReactDOM from 'react-dom';
import '@atlaskit/css-reset';

import Dashboard from './dashboard/dashboard.js'

class App extends React.Component {
    render() {
        return (
            <Dashboard />
        )
    }
};

ReactDOM.render(<App />, document.getElementById('root'));

