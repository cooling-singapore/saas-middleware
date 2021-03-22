import React from 'react';
import clsx from 'clsx';
import { makeStyles } from '@material-ui/core/styles';
import CssBaseline from '@material-ui/core/CssBaseline';
import Drawer from '@material-ui/core/Drawer';
import AppBar from '@material-ui/core/AppBar';
import Toolbar from '@material-ui/core/Toolbar';
import Typography from '@material-ui/core/Typography';
import Divider from '@material-ui/core/Divider';
import IconButton from '@material-ui/core/IconButton';
import Badge from '@material-ui/core/Badge';

import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import DashboardIcon from '@material-ui/icons/Dashboard';
import PeopleIcon from '@material-ui/icons/People';

import {
    BrowserRouter as Router,
    Switch,
    Route,
    Link,
    Redirect
} from "react-router-dom";

import MenuIcon from '@material-ui/icons/Menu';
import ChevronLeftIcon from '@material-ui/icons/ChevronLeft';
import NotificationsIcon from '@material-ui/icons/Notifications';

import Footer from './footer.js'
import Setting from './setting.js'
import DomainView from './domainView.js'
import AdminView from './adminView.js'
import SignIn from './signIn.js'

const drawerWidth = 240;

const useStyles = makeStyles((theme) => ({
    root: {
        display: 'flex',
    },
    toolbar: {
        paddingRight: 24, // keep right padding when drawer closed
    },
    toolbarIcon: {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'flex-end',
        padding: '0 8px',
        ...theme.mixins.toolbar,
    },
    appBar: {
        zIndex: theme.zIndex.drawer + 1,
        transition: theme.transitions.create(['width', 'margin'], {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.leavingScreen,
        }),
    },
    appBarShift: {
        marginLeft: drawerWidth,
        width: `calc(100% - ${drawerWidth}px)`,
        transition: theme.transitions.create(['width', 'margin'], {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.enteringScreen,
        }),
    },
    menuButton: {
        marginRight: 36,
    },
    menuButtonHidden: {
        display: 'none',
    },
    title: {
        flexGrow: 1,
    },
    drawerPaper: {
        position: 'relative',
        whiteSpace: 'nowrap',
        width: drawerWidth,
        transition: theme.transitions.create('width', {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.enteringScreen,
        }),
    },
    drawerPaperClose: {
        overflowX: 'hidden',
        transition: theme.transitions.create('width', {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.leavingScreen,
        }),
        width: theme.spacing(7),
        [theme.breakpoints.up('sm')]: {
            width: theme.spacing(9),
        },
    },
    appBarSpacer: theme.mixins.toolbar,
    content: {
        flexGrow: 1,
        height: '100vh',
        overflow: 'auto',
        padding: theme.spacing(2)
    },
    container: {
        paddingTop: 10,
        paddingBottom: 10,
    },
    paper: {
        padding: theme.spacing(2),
        display: 'flex',
        overflow: 'auto',
        flexDirection: 'column',
    },
    fixedHeight: {
        height: 240,
    },
    link: {
        color: '#D3D3D3',
        '&:hover': {
            color: 'white'
        }
    }
}));

export default function Dashboard() {
    const classes = useStyles();
    const [open, setDrawerOpen] = React.useState(false);
    const handleDrawerOpen = () => {
        setDrawerOpen(true);
    };
    const handleDrawerClose = () => {
        setDrawerOpen(false);
    };

    const [isLoginPage, setIsLoginPage] = React.useState(true);
    const [isAdmin, setIsAdmin] = React.useState(true);
    const handleSignIn = (isAdminLogin) => {
        setIsLoginPage(false);
        setIsAdmin(isAdminLogin);
    };

    const handleSignOut = () => {
        setIsLoginPage(true);
        setIsAdmin(false);
    };

    return (
        <div className={classes.root}>
            <CssBaseline />
            <Router>
            <AppBar position='absolute' className={clsx(classes.appBar, open && classes.appBarShift)}>
                <Toolbar className={classes.toolbar}>
                    {!isLoginPage &&
                        <IconButton
                            edge='start'
                            color='inherit'
                            aria-label='open drawer'
                            onClick={handleDrawerOpen}
                            className={clsx(classes.menuButton, open && classes.menuButtonHidden)}
                        >
                            <MenuIcon />
                        </IconButton>
                    }
                    <Typography variant='h5' color='inherit' noWrap className={classes.title}>
                        SaaS Middleware Dashboard
                    </Typography>
                    {!isLoginPage &&
                        <IconButton color='inherit'>
                            <Badge badgeContent={4} color='secondary'>
                                <NotificationsIcon />
                            </Badge>
                        </IconButton>
                    }
                    {!isLoginPage && 
                        <Setting handleSignOut={handleSignOut} />
                    }
                </Toolbar>
            </AppBar>
                {!isLoginPage &&
                    <Drawer
                        variant='permanent'
                        classes={{
                            paper: clsx(classes.drawerPaper, !open && classes.drawerPaperClose),
                        }}
                        open={open}
                    >
                        <div className={classes.toolbarIcon}>
                            <IconButton onClick={handleDrawerClose}>
                                <ChevronLeftIcon />
                            </IconButton>
                        </div>
                        <Divider />
                        <div>
                            <ListItem button component={Link} to="/domainView">
                                <ListItemIcon>
                                    <DashboardIcon />
                                </ListItemIcon>
                                <ListItemText primary="Domain View" />
                            </ListItem>
                            {isAdmin &&
                                <ListItem button component={Link} to="/adminView">
                                    <ListItemIcon>
                                        <PeopleIcon />
                                    </ListItemIcon>
                                    <ListItemText primary="User Management" />
                                </ListItem>
                            }
                        </div>
                    </Drawer>
                }
                <main className={classes.content}>
                    <div className={classes.appBarSpacer} />
                    <Switch>
                        <Route exact path="/">
                            <Redirect to="/login" />
                        </Route>
                        <Route path="/login">
                            <SignIn onHandleLogin={handleSignIn} />
                        </Route>
                        <Route path="/domainView">
                            <DomainView />
                        </Route>
                        <Route path="/adminView">
                            <AdminView />
                        </Route>
                    </Switch>
                    <Footer />
                </main>
            </Router>
        </div>
    );
}
