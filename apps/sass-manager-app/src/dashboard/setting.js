import React from 'react';
import {
    Menu,
    MenuItem,
    IconButton,
} from '@material-ui/core';

import SettingsIcon from '@material-ui/icons/Settings';

export default function Setting() {
    const [anchorEl, setAnchorEl] = React.useState(null);

    const handleClick = (event) => {
        setAnchorEl(event.currentTarget);
    };

    const handleClose = () => {
        setAnchorEl(null);
    };

    return (
        <div>
            <IconButton color='inherit' aria-controls='setting' aria-haspopup='true' onClick={handleClick}>
                <SettingsIcon />
            </IconButton>
            <Menu
                id='setting'
                anchorEl={anchorEl}
                keepMounted
                open={Boolean(anchorEl)}
                onClose={handleClose}
            >
                <MenuItem onClick={handleClose}>Setting 1</MenuItem>
                <MenuItem onClick={handleClose}>Setting 2</MenuItem>
                <MenuItem onClick={handleClose}>Setting 3</MenuItem>
            </Menu>
        </div>
    );
}