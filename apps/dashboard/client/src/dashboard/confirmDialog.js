import React from 'react';
import {
    Button,
    Dialog,
    DialogTitle,
    DialogContent,
    DialogContentText,
    DialogActions,
    Typography
} from '@material-ui/core';

export default function ConfirmDialog({
    open,
    text,
    handleDialogClose
})
{
    return(
        <Dialog
            open={open}
            onClose={handleDialogClose}
            aria-labelledby='alert-dialog-title'
            aria-describedby='alert-dialog-description'
        >
            {/* <DialogTitle id='alert-dialog-title'><Typography variant="subtitle1" component="span">{title}</Typography></DialogTitle> */}
            <DialogContent>
                <DialogContentText id='alert-dialog-description'>
                    <Typography color="textSecondary">
                        {text}
                    </Typography>
                </DialogContentText>
            </DialogContent>
            <DialogActions>
                <Button onClick={handleDialogClose} color='primary'>
                    Cancel
                </Button>
                <Button onClick={handleDialogClose} color='primary' autoFocus>
                    Confirm
                </Button>
            </DialogActions>
        </Dialog>
    );
}