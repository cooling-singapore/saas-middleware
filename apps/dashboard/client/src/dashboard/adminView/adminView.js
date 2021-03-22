import React from 'react';
import userData from '../data/userData';
import styled from 'styled-components';
import clsx from 'clsx';
import {
    Button,
    Card,
    CardContent,
    CardActions,
    Tooltip,
    Collapse,
    IconButton,
    Dialog,
    DialogTitle,
    DialogContent,
    DialogContentText,
    DialogActions,
    Typography,
    Grid,
    makeStyles
} from '@material-ui/core';

import {
    ExpandMore,
    DeleteOutlined
} from '@material-ui/icons';

// TODO: abstract duplicated divs
const Content = styled.div`
    height:100%,
`;

const Title = styled.div`
    font-size: small;
    font-weight: bold;
`;

const Type = styled.div`
    font-size: x-small;
`;

const Container = styled(Card)`
    border-radius: 0;
    margin-bottom: 8px;
    margin-top: 8px;
`
const useStyles = makeStyles((theme) => ({
    expand: {
        transform: 'rotate(0deg)',
        marginLeft: 'auto',
        transition: theme.transitions.create('transform', {
            duration: theme.transitions.duration.shortest,
        }),
    },
    expandOpen: {
        transform: 'rotate(180deg)',
    },
}));

export default function AdminView() {
    const [userInfo] = React.useState(userData);
    const classes = useStyles();
    const [expanded, setExpanded] = React.useState(false);
    const handleExpandClick = () => {
        setExpanded(!expanded);
    };

    const [dialogOpen, setDialogOpen] = React.useState(false);
    const handleUndeployClick = () => {
        setDialogOpen(true);
    }

    const handleDialogClose = () => {
        setDialogOpen(false);
    }

    const handleDialogCloseConfirm = () => {

        setDialogOpen(false);
    }

    return (
        <Content>
            <Grid
                container
                spacing={2}
                direction='row'
                justify='left'
                alignItems='stretch'
            >
                {userInfo.userIndex.map(userEmail => {
                    const user = userInfo.users[userEmail];
                    console.log(user);
                    return (
                        user.role !== "admin" && (
                            <Grid item xs={3}>
                                <Container variant="outlined">
                                    <CardContent>
                                        <Title>Email: {user.email}</Title>
                                        <Type>Role: {user.role}</Type>
                                    </CardContent>
                                    <CardActions disableSpacing>
                                        <Tooltip title="Delete User">
                                            <IconButton aria-label="Delete">
                                                <DeleteOutlined fontSize="small" onClick={handleUndeployClick} />
                                            </IconButton>
                                        </Tooltip>

                                        <Tooltip title="Show Password">
                                            <IconButton aria-label="expand" className={clsx(classes.expand, { [classes.expandOpen]: expanded })} onClick={handleExpandClick}>
                                                <ExpandMore fontSize="small" />
                                            </IconButton>
                                        </Tooltip>
                                    </CardActions>
                                    <Collapse in={expanded} timeout="auto" unmountOnExit>
                                        <CardContent>
                                            <Type>Password: {user.password}</Type>
                                        </CardContent>
                                    </Collapse>
                                    <Dialog
                                    open={dialogOpen}
                                    onClose={handleDialogClose}
                                    aria-labelledby='alert-dialog-title'
                                    aria-describedby='alert-dialog-description'
                                >
                                    <DialogTitle id='alert-dialog-title'><Typography variant="subtitle1" component="span">Delete {user.email}</Typography></DialogTitle>
                                    <DialogContent>
                                        <DialogContentText id='alert-dialog-description'>
                                            <Typography color="textSecondary">
                                                You are removing {user.email}.
                                            </Typography>
                                        </DialogContentText>
                                    </DialogContent>
                                    <DialogActions>
                                        <Button onClick={handleDialogClose} color='primary'>
                                            Cancel
                                        </Button>
                                        <Button onClick={handleDialogCloseConfirm} color='primary' autoFocus>
                                            Confirm
                                        </Button>
                                    </DialogActions>
                                </Dialog>
                                </Container>
                            </Grid>
                        )
                    );
                })}
            </Grid>
        </Content>
    );
}