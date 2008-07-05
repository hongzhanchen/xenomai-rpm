/**
 * @file
 * Comedilib for RTDM, command, transfer, etc. related features  
 * @note Copyright (C) 1997-2000 David A. Schleef <ds@schleef.org>
 * @note Copyright (C) 2008 Alexis Berlemont <alexis.berlemont@free.fr>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
 */

#include <comedi/ioctl.h>
#include <comedi/comedi.h>

/*!
 * @ingroup level1_lib
 * @defgroup async1_lib Command syscall API
 * @{
 */

/**
 * @brief Send a command to a Comedi device
 *
 * The function comedi_snd_command() triggers asynchronous
 * acquisition.
 *
 * @param[in] dsc Device descriptor filled by comedi_open() (and
 * optionally comedi_fill_desc())
 * @param[in] cmd Command structure
 *
 * @return 0 on success, otherwise a negative error code.
 *
 */
int comedi_snd_command(comedi_desc_t * dsc, comedi_cmd_t * cmd)
{
	/* Basic checking */
	if (dsc == NULL || dsc->fd < 0)
		return -EINVAL;

	return __sys_ioctl(dsc->fd, COMEDI_CMD, cmd);
}

/**
 * @brief Cancel an asynchronous acquisition
 *
 * The function comedi_snd_cancel() is devoted to stop an asynchronous
 * acquisition configured thanks to a Comedi command.
 *
 * @param[in] dsc Device descriptor filled by comedi_open() (and
 * optionally comedi_fill_desc())
 * @param[in] idx_subd Subdevice index
 *
 * @return 0 on success, otherwise a negative error code.
 *
 */
int comedi_snd_cancel(comedi_desc_t * dsc, unsigned int idx_subd)
{
	/* Basic checking */
	if (dsc == NULL || dsc->fd < 0)
		return -EINVAL;

	return __sys_ioctl(dsc->fd, COMEDI_CANCEL, (void *)(long)idx_subd);
}

/**
 * @brief Change the size of the asynchronous buffer
 *
 * During asynchronous acquisition, a ring-buffer enables the
 * transfers from / to user-space. Functions like comedi_read() or
 * comedi_write() recovers / sends data through this intermediate
 * buffer. The function comed_set_bufsize() can change the size of the
 * ring-buffer. Please note, there is one ring-buffer per subdevice
 * capable of asynchronous acquisition. By default, each buffer size
 * is set to 64 KB.
 *
 * @param[in] dsc Device descriptor filled by comedi_open() (and
 * optionally comedi_fill_desc())
 * @param[in] idx_subd Index of the concerned subdevice
 * @param[in] size New buffer size, the maximal tolerated value is
 * 16MB (COMEDI_BUF_MAXSIZE)
 *
 * @return 0 on success, otherwise a negative error code.
 *
 */
int comedi_set_bufsize(comedi_desc_t * dsc,
		       unsigned int idx_subd, unsigned long size)
{
	comedi_bufcfg_t cfg = { idx_subd, size };

	/* Basic checking */
	if (dsc == NULL || dsc->fd < 0)
		return -EINVAL;

	return __sys_ioctl(dsc->fd, COMEDI_BUFCFG, &cfg);
}

/**
 * @brief Get the size of the asynchronous buffer
 *
 * During asynchronous acquisition, a ring-buffer enables the
 * transfers from / to user-space. Functions like comedi_read() or
 * comedi_write() recovers / sends data through this intermediate
 * buffer. Please note, there is one ring-buffer per subdevice
 * capable of asynchronous acquisition. By default, each buffer size
 * is set to 64 KB.
 *
 * @param[in] dsc Device descriptor filled by comedi_open() (and
 * optionally comedi_fill_desc())
 * @param[in] idx_subd Index of the concerned subdevice
 * @param[out] size Buffer size
 *
 * @return 0 on success, otherwise a negative error code.
 *
 */
int comedi_get_bufsize(comedi_desc_t * dsc,
		       unsigned int idx_subd, unsigned long *size)
{
	comedi_bufinfo_t info = { idx_subd, 0, 0 };
	int ret;

	/* Basic checkings */
	if (dsc == NULL || dsc->fd < 0)
		return -EINVAL;

	if (size == NULL)
		return -EINVAL;

	ret = __sys_ioctl(dsc->fd, COMEDI_BUFINFO, &info);

	if (ret == 0)
		*size = info.buf_size;

	return ret;
}

/**
 * @brief Update the asynchronous buffer state 
 *
 * When the mapping of the asynchronous ring-buffer (thanks to
 * comedi_mmap() is disabled, common read / write syscalls have to be
 * used. 
 * In input case, comedi_read() must be used for:
 * - the retrieval of the acquired data.
 * - the notification to the Comedi layer that the acquired data have
 *   been consumed, then the area in the ring-buffer which was
 *   containing becomes available.
 * In output case, comedi_write() must be called to:
 * - send some data to Comedi layer.
 * - signal the Comedi layer that a chunk of data in the ring-buffer
 *   must be used by the driver.

 * In mmap configuration, these features are provided by unique
 * function named comedi_mark_bufrw().
 * In input case, comedi_mark_bufrw() can :
 * - recover the count of data newly available in the ring-buffer.
 * - notify the Comedi layer how many bytes have been consumed.
 * In output case, comedi_mark_bufrw() can:
 * - recover the count of data available for writing.
 * - notify Comedi that some bytes have been written.
 *
 * @param[in] dsc Device descriptor filled by comedi_open() (and
 * optionally comedi_fill_desc())
 * @param[in] idx_subd Index of the concerned subdevice
 * @param[in] cur Amount of consumed data
 * @param[out] new Amount of available data
 *
 * @return 0 on success, otherwise a negative error code.
 *
 */
int comedi_mark_bufrw(comedi_desc_t * dsc,
		      unsigned int idx_subd,
		      unsigned long cur, unsigned long *new)
{
	int ret;
	comedi_bufinfo_t info = { idx_subd, 0, cur };

	/* Basic checkings */
	if (dsc == NULL || dsc->fd < 0)
		return -EINVAL;

	if (new == NULL)
		return -EINVAL;

	ret = __sys_ioctl(dsc->fd, COMEDI_BUFINFO, &info);

	if (ret == 0)
		*new = info.rw_count;

	return ret;
}

/**
 * @brief Get the available data count
 *
 * @param[in] dsc Device descriptor filled by comedi_open() (and
 * optionally comedi_fill_desc())
 * @param[in] idx_subd Index of the concerned subdevice
 * @param[in] ms_timeout The number of miliseconds to wait for some
 * data to be available. Passing COMEDI_INFINITE causes the caller to
 * block indefinitely until some data is available. Passing
 * COMEDI_NONBLOCK causes the function to return immediately without
 * waiting for any available data
 *
 * @return the available data count.
 *
 */
int comedi_poll(comedi_desc_t * dsc,
		unsigned int idx_subd, unsigned long ms_timeout)
{
	int ret;
	comedi_poll_t poll = { idx_subd, ms_timeout };

	/* Basic checkings */
	if (dsc == NULL || dsc->fd < 0)
		return -EINVAL;

	ret = __sys_ioctl(dsc->fd, COMEDI_POLL, &poll);

	/* There is an ugly cast, but it is the only way to stick with
	   the original Comedi API */
	if (ret == 0)
		ret = (int)poll.arg;

	return ret;
}

/**
 * @brief Map the asynchronous ring-buffer into a user-space
 *
 * @param[in] dsc Device descriptor filled by comedi_open() (and
 * optionally comedi_fill_desc())
 * @param[in] idx_subd Index of the concerned subdevice
 * @param[int] size Size of the buffer to map
 * @param[out] ptr Address of the pointer containing the assigned
 * address on return
 *
 * @return 0 on success, otherwise a negative error code.
 *
 */
int comedi_mmap(comedi_desc_t * dsc,
		unsigned int idx_subd, unsigned long size, void **ptr)
{
	int ret;
	comedi_mmap_t map = { idx_subd, size, NULL };

	/* Basic checkings */
	if (dsc == NULL || dsc->fd < 0)
		return -EINVAL;

	if (ptr == NULL)
		return -EINVAL;

	ret = __sys_ioctl(dsc->fd, COMEDI_MMAP, &map);

	if (ret == 0)
		*ptr = map.ptr;

	return ret;
}

/** @} Command syscall API */

/*!
 * @ingroup level2_lib
 * @defgroup async2_lib Command syscall API
 * @{
 */

/**
 * @brief Perform asynchronous read operation on the analog input
 * subdevice
 *
 * The function comedi_async_read() is only useful for acquisition
 * configured through a Comedi command.
 *
 * @param[in] dsc Device descriptor filled by comedi_open() (and
 * optionally comedi_fill_desc())
 * @param[out] buf Input buffer
 * @param[in] nbyte Number of bytes to read
 * @param[in] ms_timeout The number of miliseconds to wait for some
 * data to be available. Passing COMEDI_INFINITE causes the caller to
 * block indefinitely until some data is available. Passing
 * COMEDI_NONBLOCK causes the function to return immediately without
 * waiting for any available data
 *
 * @return Number of bytes read, otherwise negative error code.
 *
 */
int comedi_async_read(comedi_desc_t * dsc,
		      void *buf, size_t nbyte, unsigned long ms_timeout)
{
	/* Basic checking */
	if (dsc == NULL)
		return -EINVAL;

	/* The function comedi_poll() is useful only if 
	   the timeout is not COMEDI_INFINITE (== 0) */
	if (ms_timeout != COMEDI_INFINITE) {
		int ret;

		ret = comedi_poll(dsc, dsc->idx_read_subd, ms_timeout);
		if (ret < 0)
			return ret;

		/* If the timeout value is equal to COMEDI_NONBLOCK,
		   there is no need to call the launch any read operation */
		if (ret == 0 && ms_timeout == COMEDI_NONBLOCK)
			return ret;
	}

	/* One more basic checking */
	if (dsc->fd < 0)
		return -EINVAL;

	/* Performs the read operation */
	return comedi_sys_read(dsc->fd, buf, nbyte);
}

/**
 * @brief Perform asynchronous write operation on the analog input
 * subdevice
 *
 * The function comedi_async_write() is only useful for acquisition
 * configured through a Comedi command.
 *
 * @param[in] dsc Device descriptor filled by comedi_open() (and
 * optionally comedi_fill_desc())
 * @param[in] buf Ouput buffer
 * @param[in] nbyte Number of bytes to write
 * @param[in] ms_timeout The number of miliseconds to wait for some
 * free area to be available. Passing COMEDI_INFINITE causes the
 * caller to block indefinitely until some data is available. Passing
 * COMEDI_NONBLOCK causes the function to return immediately without
 * waiting any available space to write data.
 *
 * @return Number of bytes written, otherwise negative error code.
 *
 */
int comedi_async_write(comedi_desc_t * dsc,
		       void *buf, size_t nbyte, unsigned long ms_timeout)
{
	/* Basic checking */
	if (dsc == NULL)
		return -EINVAL;

	/* The function comedi_poll() is useful only if 
	   the timeout is not COMEDI_INFINITE (== 0) */
	if (ms_timeout != COMEDI_INFINITE) {
		int ret;

		ret = comedi_poll(dsc, dsc->idx_write_subd, ms_timeout);
		if (ret < 0)
			return ret;

		/* If the timeout value is equal to COMEDI_NONBLOCK,
		   there is no need to call the launch any read operation */
		if (ret == 0 && ms_timeout == COMEDI_NONBLOCK)
			return ret;
	}

	/* One more basic checking */
	if (dsc->fd < 0)
		return -EINVAL;

	/* Performs the write operation */
	return comedi_sys_write(dsc->fd, buf, nbyte);
}

/** @} Command syscall API */
