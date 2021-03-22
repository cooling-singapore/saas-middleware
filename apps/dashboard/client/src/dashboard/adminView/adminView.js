import React from 'react';
import userData from '../data/userData';

export default function AdminView() {
    const [userInfo] = React.useState(userData);
    
    return (
        <div>
            <p>Admin page goes here! </p>
        </div>
    );
}