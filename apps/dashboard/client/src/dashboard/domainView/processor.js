import React from "react";
import styled from "styled-components";
import clsx from "clsx";
import { Draggable } from "react-beautiful-dnd";
import {
    Card,
    CardHeader,
    CardContent,
    CardActions,
    Tooltip,
    Collapse,
    IconButton,
    makeStyles
} from "@material-ui/core";

import {
    green,
    red,
    yellow
} from "@material-ui/core/colors";

import {
    ExpandMore,
    FiberManualRecord,
    DeleteOutlined
} from "@material-ui/icons";

import ConfirmDialog from "../confirmDialog"
import Job from "./job"

const Container = styled(Card)`
    border-radius: 0;
    margin-bottom: 8px;
    margin-top: 8px;
    background-color: ${props => (props.isDragDisabled ? "lightgrey" : props.isDragging ? "lightgreen" : "white")};
`;

const Title = styled.div`
    font-size: small;
    font-weight: bold;
`;

const Type = styled.div`
    font-size: x-small;
`;

const useStyles = makeStyles((theme) => ({
    expand: {
        transform: "rotate(0deg)",
        marginLeft: "auto",
        transition: theme.transitions.create("transform", {
            duration: theme.transitions.duration.shortest,
        }),
    },
    expandOpen: {
        transform: "rotate(180deg)",
    },
}));

export default function Processor(props) {
    const classes = useStyles();
    const [expanded, setExpanded] = React.useState(false);
    const handleExpandClick = () => {
        setExpanded(!expanded);
    };

    const [open, setOpen] = React.useState(false);

    const handleDialogOpen = () => {
        setOpen(true);
    };

    const handleDialogClose = () => {
        setOpen(false);
        props.onDeleteProcessor(props.processorId);
    };

    var statusLabel;
    var statusColor;
    switch (props.item.status) {
        case 1:
            statusLabel = "Idle";
            statusColor = green[500];
            break;
        case 2:
            statusLabel = "Work";
            statusColor = yellow[500];
            break;
        case 3:
            statusLabel = "Busy";
            statusColor = red[500];
            break;
    }
    return (
        <div>
            <Draggable
                draggableId={props.item.id}
                index={props.index}
                isDragDisabled={true}>
                {(provided, snapshot) => (
                    <Container
                        {...provided.draggableProps}
                        {...provided.dragHandleProps}
                        ref={provided.innerRef}
                        isDragging={snapshot.isDragging}
                        isDragDisabled={true}
                    >
                        <CardHeader
                            action={
                                <Tooltip title={statusLabel}>
                                    <FiberManualRecord fontSize="large" style={{ color: statusColor }} />
                                </Tooltip>
                            }
                            title={<Title>{props.item.name}</Title>}
                            subheader={<Type>{props.item.type}</Type>}
                        />
                        {/* <CardContent>
                        //TODO: display node status
                    </CardContent> */}
                        <CardActions disableSpacing>
                            <Tooltip title="Undeploy">
                                <IconButton aria-label="undeploy">
                                    <DeleteOutlined fontSize="small" onClick={handleDialogOpen} />
                                </IconButton>
                            </Tooltip>

                            <Tooltip title="Show Jobs">
                                <IconButton aria-label="expand" className={clsx(classes.expand, { [classes.expandOpen]: expanded })} onClick={handleExpandClick}>
                                    <ExpandMore fontSize="small" />
                                </IconButton>
                            </Tooltip>
                        </CardActions>
                        <Collapse in={expanded} timeout="auto" unmountOnExit>
                            <CardContent>
                                {props.item.jobs.map((job, index) => <Job key={index} value={job} />)}
                            </CardContent>
                        </Collapse>
                    </Container>
                )}
            </Draggable>
            <ConfirmDialog open={open} text={"Are you sure to undeploy " + props.item.name + " from " + props.nodeName} handleDialogClose={handleDialogClose}/>
        </div>
    );

}