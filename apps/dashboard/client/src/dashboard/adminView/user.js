import React from 'react';
import styled from 'styled-components';
import {
    Card,
    CardContent,
    CardActions,
    Tooltip,
    IconButton,
    Grid,
    Typography,
    makeStyles,
    Chip,
    FormControl,
    Select,
    Input,
    InputLabel,
    MenuItem
} from '@material-ui/core';

import {
    DeleteOutlined,
    VisibilityOff,
    Add,
    Done
} from '@material-ui/icons';

import ConfirmDialog from "../confirmDialog"

const Container = styled(Card)`
    border-radius: 0;
    margin-bottom: 8px;
    margin-top: 8px;
`

const useStyles = makeStyles((theme) => ({
    formControl: {
        minWidth: 120,
        maxWidth: 300,
    },
    chips: {
        display: 'flex',
        flexWrap: 'wrap',
    },
    noTextTransform: {
        textTransform: 'none'
    },
    chip: {
        margin: theme.spacing(0.5),
    }
}));


export default function User({user, keyIndex, onDeleteKey, onAddKey, onDeleteUser}) {
    const classes = useStyles();

    const [deleteUserConfirmOpen, setDeleteUserConfirmOpen] = React.useState(false);
    const handleDeleteUser = () => {
        setDeleteUserConfirmOpen(true);
    }

    const handleDeleteUserClose = () => {
        setDeleteUserConfirmOpen(false);
        
    };

    const handleDeleteUserConfirm = () => {
        setDeleteUserConfirmOpen();
        onDeleteUser(user)
    };

    const [show, setShow] = React.useState(false);
    const handlePasswordVisibility = () => {
        setShow(!show);
    }

    const handleDeleteKey = (k) => {
        // onDeleteKey(user, k);
    };

    const handleAddKey = () => {
        console.log("add key");
    };

    const [keys, setKeys] = React.useState(user.dataKeys);
    const handleChange = (event) => {
        console.log(event);
        setKeys(event.target.value);
    };

    return (
        <Grid item xs={3}>
            <Container variant="outlined">
                <CardContent style={{minHeight: '200px'}}>
                    <Typography variant="subtitle1" className={classes.noTextTransform} gutterBottom>
                        Email: {user.email}
                    </Typography>
                    <Typography variant="body2">
                        Name: {user.name}
                    </Typography>
                    <Typography variant="body2">
                        Password: 
                        <IconButton
                            onClick={handlePasswordVisibility}
                            edge="end"
                        >
                            { show ? <Typography variant="body2">{user.password}</Typography> : <VisibilityOff />}
                        </IconButton>
                        
                    </Typography>
                 
                    <FormControl className={classes.formControl}>
                    <InputLabel id="mutiple-chip-label">Keys</InputLabel>
                        <Select
                        labelId="mutiple-chip-label"
                        id="mutiple-chip"
                        multiple
                        value={keys}
                        onChange={handleChange}
                        input={<Input id="select-multiple-chip" />}
                        renderValue={(selected) => (
                            <div>
                            {selected.map((value) => (
                                <Chip key={value} label={value} size="small" onDelete={value === 'USER' ? undefined : ()=>handleDeleteKey(value)}  className={classes.chip} />
                            ))}
                            </div>
                        )}
                        >
                        {keyIndex.map((k) => (
                            <MenuItem
                            key={k}
                            value={k}
                            >
                            {k}
                            </MenuItem>
                        ))}
                        </Select>
                    </FormControl>
                </CardContent>
                <CardActions disableSpacing>
                    <Tooltip title="Delete User">
                        <IconButton aria-label="Delete">
                            <DeleteOutlined fontSize="small" onClick={handleDeleteUser} />
                        </IconButton>
                    </Tooltip>
                </CardActions>
            </Container>
            <ConfirmDialog open={deleteUserConfirmOpen} text={"Are you sure to delete " + user.name} handleDialogCancel={handleDeleteUserClose} handleDialogConfirm={handleDeleteUserConfirm}/>
        </Grid>
    );
}